# 実装前に攻撃者の視点でレビューさせるプロンプト / Prompts for an Adversarial Review Before Coding

Amazon FSx for NetApp ONTAP を使うワークロードの仕様、AWS CloudFormation テンプレート、構成図、IAM ポリシー、S3 Access Points のポリシーを、コードを書く前に AI エージェント（Kiro、Claude Code、その他のコーディングエージェント）に攻撃者の視点で読ませるためのプロンプトです。<...> を自分の値に置き換えて貼り付けます。実装後と稼働中の設定は、[読み取り専用の設定プローブ](../ontap-native/adversarial-configuration-probe.md) で確かめます。

Prompts for having an AI coding agent read, before any code is written, the specification, AWS CloudFormation template, architecture diagram, IAM policy or S3 Access Points policy of a workload on Amazon FSx for NetApp ONTAP from an attacker's viewpoint. Replace the <...> placeholders and paste. Settings after implementation and while running are checked with the read-only configuration probe.

## プロンプトの使い分け / Which One to Use

| 状況 / Situation | 使うプロンプト / Prompt |
|---|---|
| 仕様や構成図の段階で、攻撃経路と止める制御を洗い出したい / At the spec or diagram stage, list attack paths and the controls that stop them | プロンプト A（設計レビュー）/ Prompt A (design review) |
| テンプレートや IAM・アクセスポイントのポリシーの差分を、マージ前に止めるか判定したい / Decide whether a template or policy diff may merge | プロンプト B（マージ前のライン停止判定）/ Prompt B (stop-the-line check before merge) |

どちらのプロンプトも、**推測と文書の記述を分けてラベルを付ける規則** と、**`docs/agent/evidence-ledger.json` の ID なしにベンダーの制約を断言しない規則** を含みます。この 2 つは外さないでください。

Both prompts carry the rule to label inference separately from what a document states, and the rule not to assert a vendor limit without an ID from `docs/agent/evidence-ledger.json`. Do not remove either.

---

## プロンプト A: 設計レビュー / Prompt A: Design Review

```text
あなたは AWS と NetApp ONTAP のセキュリティに詳しいレビュアーです。次の成果物を、実装を始める前に、
攻撃者の視点でレビューしてください。コードは書かず、変更もしないでください。

## 対象
- 種類: <仕様 / CloudFormation テンプレート / 構成図 / IAM ポリシー / S3 Access Points のポリシー>
- 場所: <パスまたは URL>
- 前提にしてよい参照: <このリポジトリの URL またはパス>（AGENTS.md、docs/agent/evidence-ledger.json、
  docs/ontap-native/adversarial-configuration-probe.md、docs/ja/cyber-resilience-framework-mapping.md を先に全部読む）

## 列挙する攻撃経路（少なくとも次の 5 つ。成果物から読み取れる他の経路も加える）
1. データプロトコル（NFS / SMB）の認証情報を盗まれた
2. ONTAP 管理者（fsxadmin など）または AWS の管理者の認証情報を盗まれた
3. S3 Access Points の権限を持つエージェントやアプリケーションが乗っ取られた
4. 内部の管理者がスナップショットやバックアップを削除する
5. SnapMirror のピア経由でデータを持ち出す

## 各経路で答えること
- 攻撃者がその前提で何をできるか（成果物のどの記述・リソース・ステートメントがそれを許すか、行番号付き）
- それを止めるか検知する制御が、このリポジトリのどれか: ARP、Tamperproof Snapshot、SnapLock、FPolicy、
  ファイルアクセス監査と管理操作の監査、AWS Backup の論理エアギャップボールト、MAV（使える環境に限る）、
  エクスポートポリシー、共有 ACL、IAM とアクセスポイントのポリシー
- その制御が成果物に入っているか（入っている / 入っていない / 成果物からは判断できない）
- 制御の制約。例: FPolicy は S3 Access Points 経由の操作を見ない [E-015]、監査ログは S3 Access Points 経由の
  要求者を記録しない [E-018]、fsxadmin では MAV の有効化が拒否された（1 回の観測）[E-025]、AWS マネージドキーの
  ファイルシステムのバックアップはボールトへコピーされない [E-009]

## 出力
1. 表: 攻撃経路 | 攻撃者の前提 | できること | 根拠の箇所 | 止める/検知する制御 | 成果物での有無 | 重大度 | ラベル
   重大度は前提で決める。データ用インターフェイスへの到達だけ = high、データプロトコルの認証情報 = medium、
   管理者の認証情報 = low。ただし復旧点（スナップショット、バックアップ）を消せるものは high。
   ラベルは「文書（出典 URL か evidence-ledger.json の ID）」「推測」「成果物からは判断できない」のどれか。
2. ライン停止の条件に当たる項目の一覧（下の「停止条件」）。
3. 実装後に読み取り専用の設定プローブで確かめる検査 ID（ARP-001、SNAP-002、KMS-001 など）の対応。

## 守ること
- 推測は推測とラベルを付け、断定しない。ドキュメントで確認したことは出典を添える。
- 「ベンダー（AWS、NetApp）は X をできない / 対応していない」と書くときは、docs/agent/evidence-ledger.json の
  ID を添える。ID がなければ、その主張を書かずに「確認していない」と書く。
- 実在の人名、アカウント ID、リソース ID、IP、インシデント名や被害企業名を出力に書かない。
- 成果物を変更しない。修正案は差分の提案として示すだけにする。

## 停止条件（アンドン: 1 つでも当たればマージさせない）
- ファイルシステムの KMS キーが AWS マネージドキー、または KmsKeyId がない（KMS-001）
- 0.0.0.0/0 に AUTH_SYS の書き込みか superuser を許すエクスポートルール（NFS-001）
- 条件なしで Principal "*" を許すアクセスポイントポリシー、または NetworkOrigin が Internet（S3AP-001/002）
- 復旧点を管理者 1 人で消せる構成で、ロックされたスナップショットもボールトのコピーもない（SNAP-002）
- スナップショットの自動削除がオン（SNAP-003）
- 判断できない項目が停止条件に関わる場合は、停止として扱い、何が分かれば判断できるかを書く
```

```text
You are a reviewer who knows the security of AWS and NetApp ONTAP. Before any implementation starts, review
the artifact below from an attacker's viewpoint. Write no code and change nothing.

## Target
- Kind: <specification / CloudFormation template / architecture diagram / IAM policy / S3 Access Points policy>
- Location: <path or URL>
- References you may rely on: <repository URL or path> (read AGENTS.md, docs/agent/evidence-ledger.json,
  docs/ontap-native/adversarial-configuration-probe.md and docs/en/cyber-resilience-framework-mapping.md in full first)

## Attack paths to enumerate (at least these five; add others the artifact suggests)
1. Data-protocol (NFS / SMB) credentials are stolen
2. ONTAP administrator (fsxadmin or similar) or AWS administrator credentials are stolen
3. An agent or application holding S3 Access Points permissions is taken over
4. An insider administrator deletes snapshots or backups
5. Data is exfiltrated through a SnapMirror peer

## For each path, answer
- What the attacker can do with that precondition, and which statement, resource or line of the artifact allows it
- Which control in this repository stops or detects it: ARP, Tamperproof Snapshot, SnapLock, FPolicy, file access
  and administrative audit, AWS Backup logically air-gapped vault, MAV (only where available), export policy,
  share ACL, IAM and access point policies
- Whether the artifact includes that control (yes / no / cannot be told from the artifact)
- The control's limits. Examples: FPolicy does not see operations through S3 Access Points [E-015]; the audit log
  does not record the requester on that path [E-018]; enabling MAV as fsxadmin was refused in one observation
  [E-025]; backups of a file system with the AWS managed key are not copied to the vault [E-009]

## Output
1. A table: attack path | precondition | what the attacker can do | where in the artifact | control that stops or
   detects it | present in the artifact | severity | label.
   Severity follows the precondition: network reach to a data interface only = high; data-protocol credentials =
   medium; administrator credentials = low, but high when recovery points (snapshots, backups) can be destroyed.
   The label is one of "documented (source URL or evidence-ledger.json ID)", "inference", "cannot be told from the artifact".
2. The items that meet a stop condition (below).
3. The probe check IDs (ARP-001, SNAP-002, KMS-001 and so on) to run after implementation, per row.

## Rules
- Label inference as inference and do not state it as fact. Give a source for what you confirmed in documentation.
- When you write "the vendor (AWS, NetApp) cannot / does not support X", add an ID from
  docs/agent/evidence-ledger.json. Without an ID, do not make the claim; write "not checked" instead.
- Do not write real personal names, account IDs, resource IDs, IP addresses, incident names or affected companies.
- Do not change the artifact. Show fixes as proposed diffs only.

## Stop conditions (Andon: any one blocks the merge)
- The file system KMS key is the AWS managed key, or KmsKeyId is missing (KMS-001)
- An export rule gives 0.0.0.0/0 AUTH_SYS write or superuser (NFS-001)
- An access point policy allows Principal "*" with no condition, or NetworkOrigin is Internet (S3AP-001/002)
- One administrator can delete every recovery point, with no locked snapshot and no vault copy (SNAP-002)
- Snapshot autodelete is on (SNAP-003)
- If an item that cannot be decided bears on a stop condition, treat it as a stop and state what would decide it
```

---

## プロンプト B: マージ前のライン停止判定 / Prompt B: Stop-the-Line Check Before Merge

```text
次の差分を、マージしてよいか判定してください。判定だけを行い、コードやテンプレートは変更しないでください。

## 対象
- 差分: <git diff の範囲、または PR の URL>
- このリポジトリの参照: <パス>（AGENTS.md、docs/agent/evidence-ledger.json、
  docs/agent-prompts/adversarial-review.md のプロンプト A の「停止条件」を先に読む）

## やること
1. 差分に含まれる AWS::FSx::FileSystem、AWS::FSx::Volume、AWS::FSx::S3AccessPointAttachment、IAM ポリシー、
   アクセスポイントのポリシー、ONTAP の設定（エクスポートポリシー、共有 ACL、スナップショットポリシー、
   ARP、FPolicy、監査）を列挙する。
2. 各項目をプロンプト A の停止条件に照らし、「停止」「通過」「判断できない」のどれかを付ける。根拠の行番号を付ける。
3. 「判断できない」が停止条件に関わる場合は「停止」として扱う。
4. 実行してよいのは、静的なテスト（pytest tests/test_fsx_kms_customer_key.py、cfn-lint）だけ。AWS や ONTAP への
   接続、デプロイはしない。

## 出力
- 1 行目に「判定: 停止」または「判定: 通過」
- 表: 項目 | 停止条件 | 判定 | 根拠の行 | ラベル（文書 / 推測 / 判断できない）
- 停止の場合、解除に必要な変更（差分の提案）と、実装後に設定プローブで確かめる検査 ID

## 守ること
- ベンダーの制約を書くときは evidence-ledger.json の ID を添える。なければ書かない。
- 停止条件を緩める提案をしない。条件そのものに異論があれば、判定とは別に理由を書く。
```

```text
Decide whether the diff below may merge. Only decide; do not change code or templates.

## Target
- Diff: <git diff range or pull request URL>
- References in this repository: <path> (read AGENTS.md, docs/agent/evidence-ledger.json and the stop conditions
  of Prompt A in docs/agent-prompts/adversarial-review.md first)

## What to do
1. List every AWS::FSx::FileSystem, AWS::FSx::Volume, AWS::FSx::S3AccessPointAttachment, IAM policy, access point
   policy and ONTAP setting (export policy, share ACL, snapshot policy, ARP, FPolicy, audit) in the diff.
2. Mark each against the stop conditions of Prompt A as "stop", "pass" or "cannot decide", with line numbers.
3. Treat "cannot decide" on a stop condition as "stop".
4. You may run static tests only (pytest tests/test_fsx_kms_customer_key.py, cfn-lint). Do not connect to AWS or
   ONTAP and do not deploy.

## Output
- First line: "Verdict: stop" or "Verdict: pass"
- A table: item | stop condition | verdict | lines | label (documented / inference / cannot decide)
- On stop: the change needed to clear it (as a proposed diff) and the probe check IDs to run after implementation

## Rules
- Add an evidence-ledger.json ID to any vendor limit you state; without one, do not state it.
- Do not propose loosening a stop condition. If you disagree with a condition, say why separately from the verdict.
```

---

## プロンプトの確認方法 / How These Prompts Were Checked

- 停止条件は、[設定プローブ](../ontap-native/adversarial-configuration-probe.md) の検査 ID と、`tests/test_fsx_kms_customer_key.py` が静的に確かめる項目に対応させています。
- **エージェントにこのプロンプトを実際に与えて、レビューの結果を確かめたことはありません。** プロンプトの質は、使う環境で確かめてください。

- The stop conditions map to the probe's check IDs and to what `tests/test_fsx_kms_customer_key.py` checks statically.
- **Giving these prompts to an agent and checking the review it produces has not been done.** Judge the prompts in your own environment.

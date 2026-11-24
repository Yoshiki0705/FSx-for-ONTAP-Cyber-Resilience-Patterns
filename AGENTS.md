# AGENTS.md

> Project-specific instructions for AI coding agents working in this repository.

## Start here

1. [`llms.txt`](llms.txt): the document index.
2. `docs/{ja,en}/cyber-resilience-framework-mapping.md` ([JA](docs/ja/cyber-resilience-framework-mapping.md) / [EN](docs/en/cyber-resilience-framework-mapping.md)): the only NIST CSF 2.0 mapping in this repository. Other documents link to it; do not copy its tables elsewhere.
3. [`docs/agent/evidence-ledger.json`](docs/agent/evidence-ledger.json) and `make check-evidence`: register any "the vendor cannot / does not cover" claim in the ledger and cite it inline as `[E-nnn]`, in the same table cell as the claim. If you edit a line listed in `scripts/evidence_claims_baseline.json`, delete its fingerprint by hand; do not run `--update-baseline`.
4. Public documents do not name specific incidents or the companies and providers involved in them. Describe trends the way the "Threat Types Considered" section of the framework mapping does.
5. Before calling work done, run `make test` (check-evidence, ai-style, check-sensitive, check-supply-chain, cfn-lint, pytest). `make test` is offline; `make check-pinned-sha-exist` asks GitHub whether pinned Action SHAs exist, needs a token, and is not part of it. CI runs `.github/workflows/ci.yml` and `gitleaks.yml`.
6. [`docs/agent/decision-record-playbook.md`](docs/agent/decision-record-playbook.md): for multi-step tasks (new pattern, verification, IaC change) — where decision records go (`.private/tasks/`, gitignored), the evidence tier vocabulary (reuse the ledger's four: documented / verified / hypothesis / open), when to call an auditor, measuring variance before claiming an effect, and the recurring-task checklists.
7. [`docs/agent/supply-chain-policy.json`](docs/agent/supply-chain-policy.json) and `docs/{ja,en}/supply-chain-adoption-guide.md` ([JA](docs/ja/supply-chain-adoption-guide.md) / [EN](docs/en/supply-chain-adoption-guide.md)): the supply-chain policy (thresholds, cooldown values, VEX rules) and the guide that explains it. When you change a number the policy owns (cooldown, response targets, issue cap, VEX expiry), change the policy file and the number right after the matching `<!-- policy:... -->` marker in both guides in the same commit; `make check-supply-chain` fails if they differ. The three pillars and the order of work are in [`docs/{ja,en}/cyber-resilience-programme.md`](docs/en/cyber-resilience-programme.md); the ONTAP upgrade steps are in [`docs/ontap-native/ontap-upgrade-for-security-advisories.md`](docs/ontap-native/ontap-upgrade-for-security-advisories.md).
8. [`docs/agent/agent-components.json`](docs/agent/agent-components.json) and [`docs/agent/infrastructure-component-ledger.json`](docs/agent/infrastructure-component-ledger.json): the two inventory records. `make check-supply-chain` checks the first; a person matches and updates the second.
9. `scripts/handoff/cli.py --help` describes the harness that hands work to other repositories. "Layer 0" here is the harness's own term for an operating-system boundary, a macOS `sandbox-exec` profile that wraps `kiro-cli`; it has nothing to do with layers A/B/C of the SBOM in the adoption guide. The harness starts a change-mode `kiro-cli` only under layer 0, and it also re-runs an item's declared verification commands under layer 0; without it, the item is held (`os_boundary_missing`, `os_boundary_not_enforced`, `os_boundary_rerun_denied`). The profile is a deny list, so what it does not name stays open, and Apple Events, `launchctl` and `osascript` are not closed (hypothesis). What it denies is listed only in the docstring and constants of `scripts/handoff/os_boundary.py`; do not copy that list elsewhere. Besides shell and IDE configuration, it denies the places where code runs at the next start of an interpreter or editor (Python user site, pip, Neovim, Emacs and Helix configuration), the control directories of other agents on this machine, and the `hooks`, `info`, `config` and `config.worktree` of every git directory below the home directory, including submodule and linked-worktree directories; the run's own worktree stays writable. Whether `kiro-cli` writes to every added place is not measured (hypothesis; it did write to `~/.kiro/prompts` through a symbolic link before the fix), and `refs`, `HEAD`, `packed-refs` and `objects` of an unregistered repository stay open. Two things you must do: do not start a change item outside layer 0, and do not resume an item held as `worktree_gitdir_tampered`, `nested_repository_in_result`, `kiro_sandbox_enabled`, `object_import_rejected`, `branch_ref_is_symbolic` (the item's branch ref is a symbolic ref, which would make a delete or push act on another branch), `stale_ref_lock` (a ref lock file was left) or `orphan_process:<pid>` / `orphan_scan_failed` (a process started by the run was still alive after `kiro-cli` ended; the harness stops such processes with SIGKILL before it reads the result, and a person reads the item before resuming). Finding leftover processes uses a per-run token in the environment (`ps -E`) and a 0.2-second watch of the child processes. It is incomplete: a program that empties its own environment after it starts (`env -i`, or an `execve` with an empty environment), and that forks and detaches from its parent within one watch interval, is not found. The condition is the emptied environment only; whether macOS shows the environment of the binary (it hides it for binaries protected by SIP) does not matter, and an unprotected Python was not found either in one measurement. A child is caught only when its parent lives for at least one interval. A survivor that is not found can write only where layer 0 allows (the worktree, the run's own ref and its own object directory), and the tip is evaluated again before publication. The harness does not read the system git configuration, so a credential helper that is set only there does not work for `push`. Confirmed on a real machine on 2026-11-15 (kiro-cli 2.32.0): it starts, authenticates and calls the model under layer 0, and the environment variables `GIT_OBJECT_DIRECTORY` and `HANDOFF_RUN_ID` reach the child processes of the shell it runs. The same run found that `~/.kiro/prompts` is a symbolic link to a synced folder and a deny rule on the link name did not apply to the target; the profile now denies the targets too (`os_boundary.closed_names()`, `runner._symlink_targets()`, `build_profile(symlink_targets=)`), and `kiro-cli` was refused there. Keep `allowedTools` of the agent configuration to `fs_read` only: with `fs_write` or `shell` in it, `kiro-cli` ran without looking at `denyByDefault` and `allowedPaths` (checked in a throwaway directory), and the approval check rejects a configuration that contains write or shell. Not confirmed on a real machine (open): that layer 0 actually refused a write in a real run (a record of it), that the `.kiro/hooks` wiring works (the generated configuration has no hooks, and T1 records a block but its path is not confirmed), that the added deny entries (parts of `~/.kiro`, `Library/Application Support/Kiro/User`, `~/.oh-my-zsh`, and the places named above) do not stop a normal run beyond that one run, and that the token is visible in `ps -E` for the processes `kiro-cli` starts.
10. A diff that touches a file that steers agents counts as an execution surface: publish it only after the approval names the item in `execution_surface_ack`. The names and path forms that count (every path with a component that starts with a dot, and files such as `AGENTS.md`, `AGENTS.override.md`, `CLAUDE.md`, `llms.txt`, matched without regard to case) are `AGENT_CONTROL_SURFACE` in `scripts/handoff/safety.py`. A document whose name matches needs one extra approval. After you add or change an agent configuration, record its new SHA-256 in `.private/handoff/agents/approved.json` (gitignored, so a fresh clone does not have it; the maintainer creates it), run `cli.py selftest` again, and approve again: a change item runs only with a `guards_active` selftest that matches the current configuration and `kiro-cli` version.
11. The run records of the supply-chain aggregation job form a hash chain. If the watchdog reports a break because one month has two tips, or the job fails with `the month has 2 chain tips`, do not delete or edit a record: follow "Recovery when the record chain forks" in the adoption guide ([JA](docs/ja/supply-chain-adoption-guide.md#記録の連鎖が分岐したときの復旧) / [EN](docs/en/supply-chain-adoption-guide.md#recovery-when-the-record-chain-forks)). A person reads both tips and registers the abandoned one in `docs/agent/supply-chain-chain-ack.json` by pull request.

## Project Overview

FSx for ONTAP Cyber Resilience Patterns — multi-layered security reference architecture combining:
- ONTAP storage-native security (ARP, FPolicy, SnapLock; Multi-Admin Verification is documented for ONTAP, and enabling it with `fsxadmin` on FSx for ONTAP 9.18.1P6 was refused in one observation [E-025])
- TrendAI Vision One File Security (Vscan/ICAP, S3 AP integration)
- Deep Instinct for NetApp ONTAP (AI-powered zero-day prevention)
- Event-driven automated response (FPolicy → EventBridge → Step Functions)
- Audit & observability (integrates with FSx-for-ONTAP-Observability-integrations)

## Core Commands

```bash
# Lint (CloudFormation templates)
make lint

# Test (Python Lambda + template validation)
make test

# Supply-chain gates only (selftest first; offline; also run by make test)
make check-supply-chain
# Pinned Action SHAs exist on GitHub (network + GITHUB_TOKEN/GH_TOKEN; not in make test)
make check-pinned-sha-exist
# Security scan (cfn-guard + gitleaks)
make security

# Validate template
make validate

# Deploy (requires AWS credentials)
make deploy ENV=dev
```

## Coding Conventions

### Python
- Python 3.12, ARM64 Lambda target
- Type hints on all functions
- Google-style docstrings
- `from __future__ import annotations` at top
- Use `logging`, never `print()` in handlers

### CloudFormation (YAML)
- Templates in `templates/` directory
- Parameters in `parameters/` (per environment)
- cfn-lint for syntax validation
- cfn-guard for security/compliance rules
- All resources tagged: `Project`, `Layer`, `Component`
- Use `!Sub`, `!Ref`, `Fn::ImportValue` for cross-stack references
- Custom Resources (Lambda-backed) for ONTAP REST API calls

### Naming
- Directories: kebab-case
- Python modules: snake_case
- CloudFormation resource logical IDs: PascalCase
- Environment variables: UPPER_SNAKE_CASE

## Security Layers (Architecture)

```
┌─────────────────────────────────────────────────────────┐
│                    Application Layer                      │
│         (User access, IAM, AD, SVM isolation)           │
├─────────────────────────────────────────────────────────┤
│                   Network Layer                           │
│      (SG, NACL, VPC Endpoints, PrivateLink)             │
├─────────────────────────────────────────────────────────┤
│              File Scanning Layer                          │
│   TrendAI File Security │ Deep Instinct │ ONTAP Vscan   │
├─────────────────────────────────────────────────────────┤
│            Event-Driven Response Layer                    │
│    FPolicy → EventBridge → Step Functions → Actions      │
├─────────────────────────────────────────────────────────┤
│             Storage-Native Security Layer                 │
│   ARP │ SnapLock │ Tamperproof Snapshot │ MAV │ RBAC    │
├─────────────────────────────────────────────────────────┤
│               Data Protection Layer                       │
│     Snapshot │ SnapMirror │ FlexClone │ Backup          │
└─────────────────────────────────────────────────────────┘
```

## Neutrality Rule

This project compares multiple security technologies. Always:
- Present trade-offs symmetrically (include constraints of recommended options)
- Use "suited for" / "trade-off" framing, never "better than" / "beats"
- Include a "how to choose" section in every comparison document

## Testing

- Framework: pytest + hypothesis (Python Lambda functions)
- Coverage target: 80%
- CloudFormation: cfn-lint validation + cfn-guard compliance checks
- Template tests: pytest with cfn-lint programmatic API
- Integration tests: tagged `e2e-*`, excluded from CI

## Documentation

- Bilingual: JA (primary) + EN
- Code/commits: English
- Conventional commits: `feat:`, `fix:`, `docs:`, `chore:`, `sec:`
- Topic documents and runbooks (`docs/ontap-native/`, `docs/runbooks/`, `docs/data-protection/`, `docs/architecture/`) are single files with Japanese and English side by side (`## 日本語 / English` headings). New documents of this kind follow the same form.
- `docs/ja/` and `docs/en/` hold split pairs: change both in the same commit and keep the same headings and table rows.
- `docs/articles/*` are first-person articles published under the author's name, in English with a Japanese summary (`## 日本語サマリ`). Do not edit their bodies.

## Common Pitfalls

| Pitfall | Root Cause | Solution |
|---------|-----------|----------|
| ARP で持ち出しを検知できる前提で書く | ARP の検知条件として文書にあるのは書き込み系の挙動で、読み取りだけで発火する条件は文書にない（推論）[E-012] | 監査ログと SIEM。framework mapping の持ち出し型の節と [持ち出し対応の runbook](docs/runbooks/data-exfiltration-response.md) |
| FPolicy で S3 Access Points 経由の操作を見られる前提で書く | FPolicy に届くのは NFS / SMB [E-015] | 書き込みは ARP、境界はアクセスポイントポリシーと IAM |
| AWS マネージドキーで暗号化したファイルシステムを論理エアギャップボールトで守る前提 | ファイルシステムの暗号化キーが AWS マネージドキーだと、バックアップはボールトへコピーされない [E-009]。ジョブは「Completed with issues」で完了する | ファイルシステムを CMK で作る。既存は [`deployment-guide-existing-fsxn.md`](docs/deployment-guide-existing-fsxn.md) の手順でキー種別を確認。ボールト自身のキーとは別の話（AWS 所有キーが既定） |
| S3 Access Points で削除したファイルはもう読めない前提で書く | Snapshot が残る間は `.snapshot/<名前>/<パス>` の `GetObject` で読める。`ListObjectsV2` には出ない [E-061] | アクセスポイントポリシーで `.snapshot/*` を Deny するか `snapshot_directory_access_enabled=false`。[削除後も残るコピー](docs/data-protection/deletion-requests-and-retained-copies.md) |
| Tamperproof Snapshot の作成に `expiry_time` / `-expiry-time` を使う | ロックは `snaplock_expiry_time` / `-snaplock-expiry-time` | [`tamperproof-snapshot.md`](docs/ontap-native/tamperproof-snapshot.md) |
| baseline に載った行を編集して `check-evidence` が stale で落ちる | fingerprint は行の内容から作られる | baseline から手で消し、新しい行に `[E-nnn]` を付けるか肯定形にする |
| `CAPABILITY_IAM` で InsufficientCapabilitiesException | テンプレートに名前付き IAM ロール含む | `--capabilities CAPABILITY_NAMED_IAM` を使用 |
| ファイルシステムの fsxadmin 認証情報シークレットを名前で選んで `Invalid ONTAP credentials` になる | どの FS も管理ユーザーは同名 `fsxadmin`。複数 FS があると汎用名のシークレットを取り違える。正しい対応はシークレットの `FileSystemId` / `FileSystemName` タグと説明にのみ記載 | 使う前にタグ/説明で対象 FS を確認する。認証失敗は `not authorized to access secret`（クライアントの IAM 権限不足）と `Invalid ONTAP credentials` / ONTAP `6691623`（資格情報不一致、ロックではない）に切り分ける。管理エンドポイントは VPC 内からのみ到達するので、一致確認は VPC 内の踏み台から `curl -k -u ... /api/cluster` を 1 回だけ（値は出力に残さない） |
| 管理面クライアント（Workload Factory の Lambda link 等）が古いパスワードで認証を繰り返し fsxadmin をロック | 古い/不一致のシークレットを使ったまま authenticate を再試行すると ONTAP の管理ユーザーがロックされうる | 切り分け中は認証を繰り返すクライアント（link の Lambda）を予約並列数 0 に絞って止める。パスワードをリセットしたら、その FS 用の単一シークレットを真実の源として更新し、更新日と検証状態を説明に残す。Workload Factory の Secrets Manager 認証モードは link の Lambda ロールに対象シークレットの `GetSecretValue` 権限が要る |

## Agent Output Standards

> ユーザーレベル Kiro グローバル steering のミラー。steering 未ロードの環境でも従えるようにする。

> CI: `.github/workflows/ci.yml`（根拠ゲート `check_evidence_claims.py`、文体ゲート `ai_style_rules.py`、漏洩ゲート `check_sensitive_patterns.py --tracked`、サプライチェーンのゲート `check_supply_chain.py`、cfn-lint、pytest）と `gitleaks.yml`（シークレット）。ローカルでは `make test` が同じゲートを回す。命名・中立性・JA/EN parity を見る CI ゲートはないので、下の規則を手で確かめる。

### Naming (NetApp / AWS)

- 初出は **Amazon FSx for NetApp ONTAP**、以降 **FSx for ONTAP**。`FSxN` / 単独 `FSx` / `FSx ONTAP` は不可。アクセスポイントは **S3 Access Points** と略さずに書く（`S3 AP` は AWS が認めた略称ではない）。Amazon S3 のアクセスポイントと紛れる場所では **FSx for ONTAP S3 Access Points**。**既存の記述は据え置きで、一括置換はしない。**
- NetApp Console（旧 BlueXP）と NetApp Workload Factory は管理面の選択肢として扱ってよい。CLI / REST API / System Manager / NetApp Console / Workload Factory を用途別に並べ、各経路のトレードオフ（link 前提、課金、第 2 世代の複数 HA ペア非対応、AWS コンソールとの同期ラグなど）を対称に書く。特定の経路を推奨・優越として押し出さない。製品名は公式表記に合わせる（**NetApp Console**、必要なら初出で「NetApp Console（旧 BlueXP）」、**NetApp Workload Factory**）。
- 例外: 外部引用タイトルの逐語引用（その行に `allow:naming` コメントを付与）。

### Vendor neutrality (right-tool-for-the-job)

- ベンダー対決/優劣表現は禁止（"best", "beats X", "X より優れている", "競合ツール", "優位性", "game-changer"）。選択肢として提示し、推奨案自身の制約も含めてトレードオフを対称に記載。

### Public-output safety

- 個人名/ペルソナ名・メール・AWS アカウントID・内部IP/ホスト名・サポートケース番号・ベンダー内部チケットID をコミットしない。role ベース表記（"Storage Specialist lens"）と "an internal product request (tracked)" を使う。
- プロセスメタデータのノイズ禁止（"Persona Review Summary"・レビューラウンド・日付・レンズ数）。注記のラベルは話題名にする（`> **セキュリティに関する補足**:` / `> **Security note**:`）。役割名・人名のラベルは付けない。provenance は `.private/`（gitignore）へ。

### Bilingual docs (JA primary + EN)

- JA/EN parity を維持（セクション構成/数の一致、inline note の対応）。片方を変更したら同じ変更で両方に反映。

### Writing quality（AI 調・可読性の検出）

- 判定基準の本体は Hub の 1 ファイル: https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/agent/writing-quality.md
- このリポジトリの検出器は `tools/ai_style_rules.py`（Hub からのバイト単位コピー）。`make ai-style` は fail-tier の所見（D1/D2/D5/D14）で gate し、`make test` の前提として走る。warning は件数の表示のみ。

### Benchmark / evidence（性能・コスト数値のばらつき）

- 1 回の測定値で変更の効果や優劣を主張しない。変更の効果を言う前に、変更していない構成の
  ランごとのばらつきを先に測り、変更の差がそのばらつきの範囲内ならノイズとして扱う（そう書くか、
  ばらつきを超えるまで反復数を増やす）。1 回ずつしか測っていない「A は B より速い」も同じ。
- 性能・コスト数値には測定環境（ONTAP 版 / リージョン / 構成 / 測定日）を併記する。例: README の
  「ARP 検知から 2 分未満でブロック」は `ONTAP 9.17.1P7D1 で測定` を添えている。`benchmarks/` の
  結果も同様に環境併記する。
- sample run（特定の 1 回の測定）と production estimate（スケール仮定からの見積り）を区別して
  ラベルする。見積りを measured 値のように書かない。

```bash
gitleaks detect --config .gitleaks.toml --no-git --source .
make test   # check-evidence, ai-style, check-sensitive, check-supply-chain, cfn-lint, pytest (CI: .github/workflows/ci.yml)
```

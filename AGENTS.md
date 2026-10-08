# AGENTS.md

> Project-specific instructions for AI coding agents working in this repository.

## Start here

1. [`llms.txt`](llms.txt): the document index.
2. `docs/{ja,en}/cyber-resilience-framework-mapping.md` ([JA](docs/ja/cyber-resilience-framework-mapping.md) / [EN](docs/en/cyber-resilience-framework-mapping.md)): the only NIST CSF 2.0 mapping in this repository. Other documents link to it; do not copy its tables elsewhere.
3. [`docs/agent/evidence-ledger.json`](docs/agent/evidence-ledger.json) and `make check-evidence`: register any "the vendor cannot / does not cover" claim in the ledger and cite it inline as `[E-nnn]`, in the same table cell as the claim. If you edit a line listed in `scripts/evidence_claims_baseline.json`, delete its fingerprint by hand; do not run `--update-baseline`.
4. Public documents do not name incidents, companies or providers. Describe trends the way the "Threat Types Considered" section of the framework mapping does.
5. Before calling work done, run `make test` (check-evidence, ai-style, check-sensitive, cfn-lint, pytest). CI runs `.github/workflows/ci.yml` and `gitleaks.yml`.

## Project Overview

FSx for ONTAP Cyber Resilience Patterns — multi-layered security reference architecture combining:
- ONTAP storage-native security (ARP, FPolicy, SnapLock, Multi-Admin Verification)
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
| Tamperproof Snapshot の作成に `expiry_time` / `-expiry-time` を使う | ロックは `snaplock_expiry_time` / `-snaplock-expiry-time` | [`tamperproof-snapshot.md`](docs/ontap-native/tamperproof-snapshot.md) |
| baseline に載った行を編集して `check-evidence` が stale で落ちる | fingerprint は行の内容から作られる | baseline から手で消し、新しい行に `[E-nnn]` を付けるか肯定形にする |
| `CAPABILITY_IAM` で InsufficientCapabilitiesException | テンプレートに名前付き IAM ロール含む | `--capabilities CAPABILITY_NAMED_IAM` を使用 |

## Agent Output Standards

> ユーザーレベル Kiro グローバル steering のミラー。steering 未ロードの環境でも従えるようにする。

> CI: `.github/workflows/ci.yml`（根拠ゲート `check_evidence_claims.py`、文体ゲート `ai_style_rules.py`、漏洩ゲート `check_sensitive_patterns.py --tracked`、cfn-lint、pytest）と `gitleaks.yml`（シークレット）。ローカルでは `make test` が同じゲートを回す。命名・中立性・JA/EN parity を見る CI ゲートはないので、下の規則を手で確かめる。

### Naming (NetApp / AWS)

- 初出は **Amazon FSx for NetApp ONTAP**、以降 **FSx for ONTAP**。`FSxN` / 単独 `FSx` / `FSx ONTAP` は不可。アクセスポイントは **S3 Access Points** と略さずに書く（`S3 AP` は AWS が認めた略称ではない）。Amazon S3 のアクセスポイントと紛れる場所では **FSx for ONTAP S3 Access Points**。**既存の記述は据え置きで、一括置換はしない。**
- NetApp Workload Factory / NetApp Console / BlueXP は提案しない。native 等価物（CloudWatch, ONTAP REST API, FabricPool, AWS DataSync, Snapshot/FlexClone/SnapMirror）に置換。
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

### Before committing docs

```bash
gitleaks detect --config .gitleaks.toml --no-git --source .
make test   # check-evidence, ai-style, check-sensitive, cfn-lint, pytest (CI: .github/workflows/ci.yml)
```

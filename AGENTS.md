# AGENTS.md

> Project-specific instructions for AI coding agents working in this repository.

## Project Overview

FSx for ONTAP Cyber Resilience Patterns — multi-layered security reference architecture combining:
- ONTAP storage-native security (ARP, FPolicy, SnapLock, Multi-Admin Verification)
- TrendAI Vision One File Security (Vscan/ICAP, S3 AP integration)
- Deep Instinct for NetApp ONTAP (AI-powered zero-day prevention)
- Event-driven automated response (FPolicy → EventBridge → Step Functions)
- Audit & observability (integrates with fsxn-observability-integrations)

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

## Common Pitfalls

| Pitfall | Root Cause | Solution |
|---------|-----------|----------|
| AgentCore Gateway assumed us-east-1 only | Workshop examples use us-east-1 | **ap-northeast-1 で利用可能（検証済み 2026-07）**。Gateway + Lambda を同一リージョンに配置 |
| AgentCore Lambda event: `event.toolName` で取得 | 誤った前提 | `context.client_context.custom['bedrockAgentCoreToolName']` を使用。ツール名は `targetName___toolName` 形式 |
| `create-gateway-target` で Lambda not found | Gateway と Lambda のリージョン不一致 | 同一リージョン配置必須。クロスリージョン Lambda 呼び出しは不可 |
| `CAPABILITY_IAM` で InsufficientCapabilitiesException | テンプレートに名前付き IAM ロール含む | `--capabilities CAPABILITY_NAMED_IAM` を使用 |

## Agent Output Standards

> ユーザーレベル Kiro グローバル steering のミラー。steering 未ロードの環境でも従えるようにする。

> CI: `.github/workflows/agent-output-audit.yml`（命名/中立性/リーク/parity）と `gitleaks.yml`（シークレット）。

### Naming (NetApp / AWS)

- 初出は **Amazon FSx for NetApp ONTAP**、以降 **FSx for ONTAP**。`FSxN` / 単独 `FSx` / `FSx ONTAP` は不可。アクセスポイントは **S3 Access Points** と略さずに書く（`S3 AP` は AWS が認めた略称ではない）。Amazon S3 のアクセスポイントと紛れる場所では **FSx for ONTAP S3 Access Points**。
- NetApp Workload Factory / NetApp Console / BlueXP は提案しない。native 等価物（CloudWatch, ONTAP REST API, FabricPool, AWS DataSync, Snapshot/FlexClone/SnapMirror）に置換。
- 例外: 外部引用タイトルの逐語引用（その行に `allow:naming` コメントを付与）。

### Vendor neutrality (right-tool-for-the-job)

- ベンダー対決/優劣表現は禁止（"best", "beats X", "X より優れている", "競合ツール", "優位性", "game-changer"）。選択肢として提示し、推奨案自身の制約も含めてトレードオフを対称に記載。

### Public-output safety

- 個人名/ペルソナ名・メール・AWS アカウントID・内部IP/ホスト名・サポートケース番号・ベンダー内部チケットID をコミットしない。role ベース表記（"Storage Specialist lens"）と "an internal product request (tracked)" を使う。
- プロセスメタデータのノイズ禁止（"Persona Review Summary"・レビューラウンド・日付・レンズ数）。レビュー知見は inline の role-based lens note（`> **Topic** (Role lens): ...`）として織り込み、provenance は `.private/`（gitignore）へ。

### Bilingual docs (JA primary + EN)

- JA/EN parity を維持（セクション構成/数の一致、inline note の対応）。片方を変更したら同じ変更で両方に反映。

### Before committing docs

```bash
gitleaks detect --config .gitleaks.toml --no-git --source .
# CI が agent-output チェックをミラー: .github/workflows/agent-output-audit.yml
```

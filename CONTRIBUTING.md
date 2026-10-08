# Contributing to FSx for ONTAP Cyber Resilience Patterns

Thank you for your interest in contributing! This project welcomes contributions from the community.

## Getting Started

### Prerequisites

- Python 3.12+
- make
- AWS CLI v2 (for deployment only — not needed for linting/testing)

### Local Development Setup

```bash
# Clone
git clone https://github.com/Yoshiki0705/FSx-for-ONTAP-Cyber-Resilience-Patterns.git
cd FSx-for-ONTAP-Cyber-Resilience-Patterns

# Install dev dependencies
python3 -m pip install -r requirements-dev.txt

# Run linting (no AWS credentials needed)
make lint

# Run tests (no AWS credentials needed)
make test

# Run security checks
make security
```

## How to Contribute

### Reporting Issues

- Use the [Bug Report](.github/ISSUE_TEMPLATE/bug_report.md) template for bugs
- Use the [Feature Request](.github/ISSUE_TEMPLATE/feature_request.md) template for enhancements
- Include reproduction steps, expected behavior, and environment details

### Submitting Changes

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/your-feature`
3. Make changes following the coding conventions below
4. Run `make test` and `make lint` to ensure passing
5. Commit with conventional commit messages
6. Open a Pull Request using the PR template

## Coding Conventions

### CloudFormation Templates

- YAML format, stored in `templates/`
- All resources must have tags: `Project`, `Environment`, `Layer`
- Validate with `cfn-lint` before committing
- Security rules checked with `cfn-guard` (see `security/guard-rules/`)

### Python (Lambda Functions)

- Python 3.12, ARM64 target
- `from __future__ import annotations` at the top of every file
- Type hints on all functions
- Google-style docstrings
- Use `logging` module, never `print()`
- Tests with pytest + hypothesis

### Naming Rules (Strict)

The authoritative version of these rules is the Agent Output Standards section of [AGENTS.md](AGENTS.md).

- First mention: **Amazon FSx for NetApp ONTAP**, thereafter **FSx for ONTAP**
- Forbidden abbreviations: `FSxN`, bare `FSx`, `FSx ONTAP`, `FSx NetApp`
- S3 Access Points: write **S3 Access Points** in full; where it could be read as an Amazon S3 access point, write **FSx for ONTAP S3 Access Points**. Do not bulk-rewrite existing short forms
- Forbidden products: NetApp Workload Factory / NetApp Console / BlueXP

### Neutrality

- No vendor-versus framing ("better than", "beats", "inferior", "competing")
- Present all technologies with symmetric trade-off descriptions
- Include "how to choose" guidance in every comparison

### Documentation

- Bilingual: Japanese (primary) + English
- Code, variables, resource names: English only

### Commit Messages

English, conventional commits format:

```
feat: add quarantine workflow step function
fix: correct SG rule for ICAP port
docs: add ARP learning period to configuration guide
chore: update cfn-lint to 1.10.3
sec: add KMS key rotation policy
```

## Security

### Never Commit

- Real AWS Account IDs (use `123456789012`)
- Real IP addresses (use `10.0.x.x` or `<management-ip>`)
- Real resource IDs (use `fs-0123456789abcdef0`)
- SSH key paths or personal file paths
- Secrets, API keys, passwords

### Supply-Chain Security

- All GitHub Actions must be pinned to SHA hashes
- `actions/checkout` must set `persist-credentials: false`
- Run `make security` before pushing

### Dependency Automation (Renovate)

This repository uses [Renovate](https://github.com/apps/renovate) for automated dependency updates. The configuration lives in `renovate.json` at the repo root.

> **Setup note**: Renovate requires the [Renovate GitHub App](https://github.com/apps/renovate) to be enabled on this repository (one-time setup by a repository admin). The `renovate.json` file only configures its behavior — it does not function without the App installed.

## Code Review Checklist

- [ ] cfn-lint passes (`make lint`)
- [ ] pytest passes (`make test`)
- [ ] No forbidden naming (FSxN, bare FSx, Workload Factory, BlueXP)
- [ ] No real IPs/account IDs/resource IDs
- [ ] No vendor-versus language
- [ ] Bilingual documentation updated (if applicable)
- [ ] Tags on all CloudFormation resources

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

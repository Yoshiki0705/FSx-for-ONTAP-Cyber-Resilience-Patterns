# Supply-Chain Adoption Guide (Pillar 1)

> **Summary**: This guide shows how to adopt the first pillar, software supply-chain visibility and response, across your own repositories. For each of the four components (inventory, exploitability-based detection and prioritization, defense at intake, and loosely coupled updates) it gives the purpose, numbered steps, the matching Policy_File keys, a pinned-reference example, and how to choose a tool. The Hub-side parts (three reusable workflows and a shared Renovate preset) are still being handed off, so the references in this guide are placeholders. The numbers match the values in [`docs/agent/supply-chain-policy.json`](../agent/supply-chain-policy.json) (the Policy_File).

## Intended readers

Two kinds of readers are expected. One is a Service_Owner role: a partner or SI, a system owner, or an application owner. The other is an AI agent that works in place of those roles. Both work within the policy and the approvals that the repository maintainer has set. An AI agent follows three rules.

- It drafts judgments only. It does not approve a VEX statement, enable automerge, or change a Response_Target without a human's approval.
- It reads numbers from the [Policy_File](../agent/supply-chain-policy.json) and does not copy the values in this guide.
- An `[E-nnn]` next to a "cannot" or "is not listed" statement is a registration number in [evidence-ledger.json](../agent/evidence-ledger.json). It does not add a claim that is not registered there.

The terms below are used under these names from here on.

| Term | Meaning |
|---|---|
| Policy_File | A JSON file that holds thresholds, waiting periods, the automerge scope, the target repositories, and the response targets. The reference for the numbers in this guide |
| Aggregator | The scheduled job on the Hub that matches each repository's SBOM against vulnerability data and opens Issues in the repository |
| Finding | One result the Aggregator produces (a combination of repository, vulnerability, and component version) |
| Opening_Threshold | The condition for opening an Issue: CVSS severity High or above, a CISA KEV listing, or a malicious package (Malicious_Package_Finding) |
| VEX_Reviewer | The human role that approves VEX statements |
| Response_Target | The target time for detection and fixing. Not called an SLO |
| Cooldown | The waiting period before a freshly published version is taken in |
| Hub | The repository that holds the Reusable_Workflows and the Renovate_Preset: [FSx-for-ONTAP-Adoption-Playbook](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook) |

The programme as a whole and its three pillars are described in the [Programme_Document](cyber-resilience-programme.md). This guide covers the adoption of the first pillar only.

## The four components and scope

| Component | What it does | Main parts |
|---|---|---|
| Inventory | Keeps a machine-readable record of what is where | SBOMs, Infrastructure_Component_Ledger, Agent_Component_Inventory |
| Detection and prioritization | Turns exploited vulnerabilities and malicious packages into Issues first | Aggregator, OpenVEX |
| Defense at intake | Keeps freshly published versions and unpinned references out | Renovate_Preset, verification gates, provenance attestation |
| Loosely coupled updates | Applies updates in small steps that can be rolled back | Automerge policy, Lambda_Canary_Reference |

### Out of scope and the limits of pinning

Out of scope: no AIBOM / ML-BOM format is produced, and the record of agent components stays a standalone JSON file outside the SBOM. Digest pinning for .NET (NuGet), Terraform, and Dockerfile `FROM` lines is not checked by this pillar. It is recorded as a subject for a later stage.

Pinning has limits. The three points below remain risks even when a reference looks pinned.

- Pinning a version does not cover changes to the tool definitions an MCP server returns (hypothesis; this is a design inference, not a vendor statement). Detecting tool-definition changes is not part of this pillar's gates. A Cloud Security Alliance research note recommends inventorying the MCP servers in use, pinning versions, and detecting definition changes. The note states that it was itself produced with AI assistance and has not had formal review ([References](#references)).
- A top-level pin (`npx -y <pkg>@<x.y.z>` or `image@sha256:…`) does not pin transitive dependencies. Pinning the whole dependency tree needs a lock file.
- An image pinned by digest does not take in security updates on its own. Updates arrive as Renovate PRs that a human reviews.

The Cooldown of <!-- policy:cooldown_days.default -->3 days is a conventional value, not a measured one. No external basis has been found for the <!-- policy:cooldown_days.major -->7 days for major updates either. The pilot will review both by looking at the number of fixes that the waiting period delayed.

Amazon Inspector's AI inventory finds self-hosted AI frameworks in EC2 instances and ECR images; the AWS Security Hub FAQ describes it. It has a different subject from this pillar's Agent_Component_Inventory, which counts files in repositories. It can complement the view of running resources, but the user guide has not been read, so check it before relying on it.

### Official configuration examples rewritten in pinned form

MCP client configuration examples are often written with `uvx <pkg>` or `npx -y <pkg>` without a version, or with an image that has only a tag. The pinned form is shown below. `<x.y.z>` and `<64 digits>` are placeholders; decide them after checking the official release. The configuration file name and key names differ by client, so check each client's documentation. This guide has not checked the documentation of seven individual clients.

```json
{
  "mcpServers": {
    "example-uvx": { "command": "uvx", "args": ["example-server==<x.y.z>"] },
    "example-uvx-from": { "command": "uvx", "args": ["--from", "example-server==<x.y.z>", "example-command"] },
    "example-npx": { "command": "npx", "args": ["-y", "example-server@<x.y.z>"] },
    "example-docker": { "command": "docker", "args": ["run", "-i", "--rm", "example/server@sha256:<64 digits>"] }
  }
}
```

A remote server specified only by `url` is recorded as "not applicable" rather than as a pinning target. A recommendation by name only (no declaration file) needs a declaration file, or a note in this guide.

## Inventory

The matching Well-Architected best practices are SEC11-BP02 and SEC11-BP05. The mapping table is in the [framework mapping](cyber-resilience-framework-mapping.md#best-practice-ids) and is not copied here.

The purpose is to be able to answer, when a vulnerability is published, "which version in which of my repositories is affected" without searching by hand.

### Steps

1. Check that your repository is in the Policy_File `target_repositories` (12 entries). If it is not, open a PR that adds it. Keep the four entries in `excluded_repositories` (the BLEA upstream repositories and forks).
2. Enable layer A, the GitHub dependency graph. The Aggregator fetches the SBOM through the API. GitHub's synchronous SBOM export API is not available from 2026-11-13 [E-044]. Use the asynchronous `generate-report` and `fetch-report` path.
3. For layer B (scanning in CI), call the Hub's `sbom-generate` from a caller workflow, pinned to a 40-character SHA. The artifact `sbom-<commit-sha>` is kept for 90 days. 90 days is the limit for public repositories; when you add a private repository, you can choose a retention of up to 400 days.
4. A repository that publishes releases attaches the SBOM of the commit that produced the release to the release. After 90 days, the composition of a release is answered by rebuilding, and the tool versions may differ from those used at the time.
5. Record agent components (MCP servers, agent settings, installation steps) in `docs/agent/agent-components.json`, and bring the number of unpinned entries to 0.
6. ONTAP versions, Amazon FSx for NetApp ONTAP (FSx for ONTAP from here on) file systems, and the versions of the TrendAI and Deep Instinct agents are not put in an SBOM. A person records them in [`infrastructure-component-ledger.json`](../agent/infrastructure-component-ledger.json). An entry is due for re-matching 90 days after the matching date.

### Policy_File keys and a pinned-reference example

The matching keys are `target_repositories`, `excluded_repositories`, and `dependency_scope.non_production_paths` (paths excluded from the production-dependency decision; the initial values are `tests/` and `docs/`). A caller workflow example follows. Replace `<40-character SHA>` with the value at the time the Hub publishes the reusable workflow. Until the Hub has a tag and the SHA reference has been shown to resolve once, a tag reference is allowed as a temporary measure. This guide has not checked whether the tag exists.

```yaml
jobs:
  sbom:
    uses: Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/.github/workflows/sbom-generate.yml@<40-character SHA> # <tag>
    permissions:
      contents: read
```

### Choosing among inventory options

Rows are options; columns are use, prerequisites, how cost is handled, and constraints. No ranking is given. The constraints of each option are written at the same level of detail (what is not visible, what has to be prepared).

| Option | Use | Prerequisites | Cost handling | Constraints |
|---|---|---|---|---|
| Repository SBOM (layers A and B) | Match the dependencies, Actions, container images, and Lambda components that a repository declares against newly published vulnerabilities in the Aggregator, and open an Issue in the repository | The GitHub dependency graph (layer A) and a CI scan (layer B). Reusable_Workflow `sbom-generate` | No AWS charges. GitHub Actions run time | What enters after deployment (OS packages, agents installed by hand, libraries bundled by a runtime) is outside the record. CI has to be set up per repository |
| Amazon Inspector SBOM export (layer C) | Write the SBOM of the resources Inspector monitors to S3 as CycloneDX 1.4 / SPDX 2.3 JSON, and hand it to external tools or an audit record | Inspector enabled for the resource type. Policies on the destination S3 bucket and KMS key | Inspector scan charges (separate pricing, or Security Hub Essentials) plus S3 and KMS charges. The charge for the export itself has not been checked | The content is as of the time the export was requested; the user builds any periodic refresh. Agent-based EC2 Windows instances cannot be exported [E-052]. Inspector does not scan the AWS SDK bundled with the Lambda runtime [E-047], functions encrypted with a customer managed key [E-048], or functions not invoked or updated in the last 90 days [E-049] |
| SBOM_Inventory | Look up in the console or API which resources in the organization contain a given package and version (including data gathered into the home Region by cross-Region aggregation) | AWS Security Hub enabled per account and Region, and Inspector enabled per resource type. A delegated administrator to see the whole organization | Included in Essentials at no additional charge ([AWS What's New](https://aws.amazon.com/about-aws/whats-new/2026/11/security-hub-sbom-inventory/), checked 2026-11-12). Essentials is priced per resource and includes Inspector standard scanning ([AWS Security Hub Pricing](https://aws.amazon.com/security-hub/pricing/), checked 2026-11-12). It is not available where Security Hub is not enabled ([Security Hub User Guide](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-v2-sbom.html), checked 2026-11-13). Unit prices are not given | The response has only name, version, type, and count, with no purl, so it cannot be matched directly against a repository SBOM [E-053]. FSx for ONTAP and ONTAP are not expected to be listed (hypothesis) [E-054]. A new SBOM can take hours to appear. The user guide and API reference do not describe export as SPDX or CycloneDX (this does not say export is impossible; it is unconfirmed) |
| Infrastructure_Component_Ledger | Match ONTAP versions, FSx for ONTAP file systems, and the versions of the TrendAI and Deep Instinct agents against NetApp and AWS security advisories | A procedure in which a person matches and records. Due for re-matching 90 days after the matching date | No AWS charges. The labor of matching | Not a machine-readable SBOM; matching is a human procedure (semi-automatic matching with RSS 2.0 as the source, with a person confirming). Changes after the matching date are not reflected until the next matching |

The steps for choosing are as follows.

1. Decide whether the subject is what a repository declares, a deployed resource, or the storage and agent base.
2. For what a repository declares, use layers A and B.
3. For deployed resources, when you want to look up across the organization where a package is installed and AWS Security Hub is enabled, use SBOM_Inventory.
4. For deployed resources, when you want to hand the SBOM to outside parties in a machine-readable form, or when Security Hub is not enabled, use layer C.
5. Record ONTAP, FSx for ONTAP, and the agents in the Infrastructure_Component_Ledger.
6. If more than one applies, use them together. For example, export with layer C the SBOM of a resource found in SBOM_Inventory and match it by purl.

This pillar does not enable Amazon Inspector or AWS Security Hub and takes no action that incurs charges. Enabling them and estimating the cost belong to the second pillar.

### Choosing an SBOM generation tool

Use tools from the same lineage for generation and scanning. Decide the pair to adopt by measuring missed findings in the pilot.

| Tool | Suited to | Trade-offs |
|---|---|---|
| Trivy alone (Trivy generates and scans) | Entrusting generation and scanning to one lineage | One distribution incident affects both generation and scanning. The default exit code is 0 even when findings exist, so set `--exit-code` explicitly. That it does not report `MAL-` is a hypothesis (not run to confirm) |
| Syft (generate) + Grype (scan) | Matching generation and scanning as a pair from the same lineage | The versions of two tools have to be pinned and updated. Syft's `-o spdx-json` emits SPDX 3.0 by default, so specify `spdx-json@2.3`. Grype's handling of SBOM input has not been read (unconfirmed) |
| Syft (generate) + Trivy (scan) | Handling both repositories and images with one scanner | Trivy's documentation warns that SBOMs made by other tools can lead to inaccurate detection. The lineages differ and findings can be missed, so measure missed findings in the pilot if you choose it |
| OSV-Scanner | Using the OSV database directly; repositories centered on lock files | Its handling of image scanning has not been read (unconfirmed) |
| Layer A only | Not adding any extra tool | Limited to the declaration files GitHub reads. What lies outside that range is not included |

Pin tools to an exact version number and an image `sha256:` digest. Decide the version and digest after checking the official release. How to verify the distribution of a pinned tool is in the section [Verifying provenance](#verifying-provenance).

## Detection and prioritization

The matching Well-Architected best practices are SEC11-BP02 and SEC11-BP05. See the [framework mapping](cyber-resilience-framework-mapping.md#best-practice-ids) for the mapping table.

The purpose is to turn exploited vulnerabilities and malicious packages into Issues first. If you order only by CVSS severity, vulnerabilities rated Medium or below that have evidence of exploitation are pushed back.

### Steps

1. Check `opening_threshold` in the Policy_File. By default an Issue is opened when any of three conditions is met: CVSS severity `HIGH` or above, a KEV listing, or a malicious package. EPSS is not used in the decision to open; it is displayed only (`epss_used_for_opening` is `false`).
2. Enable the Hub's Aggregator. The interval between scheduled runs is 12 hours or less; the design uses every 6 hours. The Hub-side implementation is still being handed off.
3. Check the Issue count. The cap on new Issues per repository per run is <!-- policy:issue_limits.max_new_issues_per_repo_per_run -->10. When the cap is exceeded, Findings that are KEV-listed or malicious packages are opened first and the rest in descending CVSS severity; the excess is listed in one summary Issue for that repository.
4. A malicious package (a `MAL-` identifier) is opened regardless of severity and is not excluded by VEX (`open_if_malicious` is always `true`). The unit for de-duplication is (repository, purl, version). If the same purl and version has both a GHSA (type=malware) and a `MAL-` record, they are merged into one, and `MAL-` is preferred as the representative identifier.
5. A withdrawn `MAL-` is closed with the reason `withdrawn` only when the OSV `GET /v1/vulns/{id}` response succeeds and `withdrawn` can be read as a timestamp. If upstream removed the affected version from the record, it is closed with `feed_version_delisted`. If the response cannot be obtained, or `withdrawn` cannot be read, the Issue is not closed and is recorded in the run result as `malicious_withdrawn_open`. If a withdrawn `MAL-` reappears, the closed Issue is reopened.
6. Check what an Issue carries: the vulnerability identifier, the affected component and version, CVSS severity, whether it is KEV-listed, whether it is a malicious package, the EPSS score and fetch date (with the model version), the fixed version, the detection time, and the Response_Target deadline. The KEV field `knownRansomwareCampaignUse` is displayed only and is not used in the decision.

Scanners that depend on a CVE database do not detect a malicious package before a CVE is assigned. The AWS Security Blog makes this point (the blog post in the [References](#references); it is guidance, not a specification). For this reason, malicious packages are looked up separately from the OpenSSF Malicious Packages feed through OSV.

### Policy_File keys

- `opening_threshold.min_cvss_severity`, `open_if_kev_listed`, `open_if_malicious`, `epss_used_for_opening`
- `issue_limits.max_new_issues_per_repo_per_run`
- `vex.exclude_statuses`, `vex.malicious_never_suppressed` (the section [Operating VEX](#operating-vex))
- `response_target.*` (the section [Response targets](#response-targets))

### Choosing a tool

Choose how to find vulnerabilities by what you want to see. The table below lists three options at the same level of detail. No ranking is given.

| Option | Suited to | Trade-offs |
|---|---|---|
| Aggregator (adopted) | Applying the same threshold across 12 repositories and tracking each in Issues per repository | Depends on a scheduled Hub job and external feeds (KEV, EPSS, OSV). Issues are per repository, so Inspector findings, which are per account and resource, are not included as sources of Issues. Deployed-state vulnerabilities that do not correspond to a repository, such as libraries bundled with a runtime, do not become Issues |
| GitHub Dependabot alerts only | Not adding any mechanism and viewing alerts on the repository's screen | Thresholds and deadlines rely on per-repository settings. In a repository where Dependabot alerts are disabled, neither alerts nor the Renovate fix PRs that read them are expected to be created (hypothesis) [E-055]. Handling of malicious packages has to be arranged separately |
| Amazon Inspector findings (aggregated in AWS Security Hub CSPM) | Viewing deployed Lambda functions, ECR images, and EC2 instances per account and Region | Requires enabling Inspector and Security Hub and their charges. No Issue is created in the repository. Code Security findings are not sent to Security Hub CSPM [E-046]. AWS Security Hub (OCSF) does not receive third-party findings, and custom findings appear only in CSPM [E-050]. The AWS SDK bundled with the Lambda runtime [E-047], functions encrypted with a customer managed key [E-048], and functions not invoked or updated in the last 90 days [E-049] are out of the scan |

When the same vulnerability appears both as an SBOM-derived Finding and as an Inspector finding, an Issue is created only from the SBOM-derived Finding. Inspector findings are handled on the Security Hub CSPM side, and the fix is made through the repository's Issue. What Inspector does not scan is not visible to the Aggregator either. Do not read "does not become an Issue" as "Inspector can catch it".

## Defending at intake

The matching Well-Architected best practices are SEC11-BP05, SEC11-BP06, and SEC11-BP07. See the [framework mapping](cyber-resilience-framework-mapping.md#best-practice-ids) for the mapping table.

The purpose is to keep freshly published versions, references without a pinned version, and artifacts whose provenance cannot be verified out of the repository.

### Steps

1. Add the Renovate_Preset to `extends` in the repository's `renovate.json`. Pin the reference to a 40-character SHA or a tag; do not reference a branch name and do not omit the reference. Do not write a provisional tag until the Hub has one.
2. Do not override `minimumReleaseAge`, `automerge`, `platformAutomerge`, or `internalChecksFilter` in the repository's own settings. The gate detects this and fails. Keep the existing `vulnerabilityAlerts` (enabled, `security` label) and `osvVulnerabilityAlerts` (enabled) at the same values.
3. Check the Cooldown values. Ordinary updates wait <!-- policy:cooldown_days.default -->3 days and major updates <!-- policy:cooldown_days.major -->7 days. Both are conventional values, not measured ones. According to Renovate's documentation, vulnerability-fix PRs are created without the Cooldown. For that reason they are not automerged and require a human approving review.
4. Enable GitHub Dependabot alerts. Renovate's vulnerability-fix path reads Dependabot alerts, so fix PRs are not expected to be created in a repository where they are disabled (hypothesis) [E-055].
5. For updates to which Renovate does not apply the Cooldown (pin, `lockFileMaintenance`) and for transitive dependencies, set a waiting period on the package-manager side. The values are the Policy_File `package_manager_wait`: <!-- policy:package_manager_wait.default_days -->3 days for ordinary updates and <!-- policy:package_manager_wait.major_days -->7 days for major updates. The setting names are npm `min-release-age`, pnpm `minimumReleaseAge`, uv `exclude-newer`, and pip `--uploaded-prior-to`. Units differ by tool (minutes, days, or durations). This guide has not checked the names and units for anything other than npm, so check each tool's current documentation.
6. Pin production dependencies to exact versions: `==` for Python, and an exact version without an operator for npm. Pin third-party GitHub Actions to a 40-character commit SHA, and tools to an exact version plus an image `sha256:` digest. The Hub's `cooldown-pinning-check` verifies pinning and that the Cooldown values match the Policy_File.
7. Call the Hub's `vex-validate` and `cooldown-pinning-check` from a caller workflow, pinned to a 40-character SHA (see the example in the section [Loosely coupled updates](#loosely-coupled-updates)).
8. A repository that publishes release artifacts follows the steps in the section [Verifying provenance](#verifying-provenance).

A malicious release disguised as a vulnerability fix can become a PR without going through the Cooldown. Before merging a fix PR, a person checks the diff, the package's publication time, and any change of publisher. Renovate's `osvVulnerabilityAlerts` is an experimental feature, so do not rely on it as the protection against malicious packages. If a `MAL-` record is published after a merge, the Aggregator opens an Issue.

Digest updates for images in registries that do not return release times (GHCR, Quay, ECR) are held indefinitely under the default `minimumReleaseAgeBehaviour` (`timestamp-required`) [E-045]. This project accepts the hold. To lift it, set `timestamp-optional` in an individual rule. Once lifted, the Cooldown does not apply to that image.

### Policy_File keys and a pinned-reference example

The matching keys are `cooldown_days.default`, `cooldown_days.major`, `package_manager_wait.default_days`, `package_manager_wait.major_days`, and `dependency_scope.non_production_paths`. A `renovate.json` example follows. Replace `<tag>` with the value at the time the Hub tags the preset.

```json
{
  "$schema": "https://docs.renovatebot.com/renovate-schema.json",
  "extends": [
    "github>Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook//renovate/supply-chain#<tag>"
  ],
  "vulnerabilityAlerts": { "enabled": true, "labels": ["security"] },
  "osvVulnerabilityAlerts": true
}
```

That this reference form resolves in Renovate has not been confirmed by running it. If the preset cannot be resolved, return the reference to the previous SHA or tag.

### Choosing a tool

There are three options for where to place the Cooldown. No ranking is given, and they can be combined.

| Option | Suited to | Trade-offs |
|---|---|---|
| Renovate `minimumReleaseAge` (adopted) | Making the update PR wait at the point it is created; keeping the value in one place, the Hub preset | Does not reach pin, `lockFileMaintenance`, or transitive dependencies. Digest updates for images in GHCR, Quay, and ECR are held indefinitely [E-045] |
| Waiting period on the package-manager side | Covering transitive dependencies and installs that do not go through Renovate | Units and setting names differ by tool, and the gate has more files to read. With npm, the waiting period can keep `npm audit fix` from installing a patched version [E-056] |
| No waiting period | Taking in fixes as fast as possible; few enough updates that a person can review all of them | A malicious release can be taken in before it is withdrawn. A person has to check each fresh version every time |

Pinning methods also involve a choice. Pinning to a commit SHA or digest prevents the target from being swapped, but it assumes updates are received through Renovate PRs. Pinning to a tag is easier to read, but a tag can be moved. A lock file with hash-checked installs (`npm ci`, `--require-hashes`) pins transitive dependencies too, but whether to make it mandatory is decided after the pilot measures the number of violations.

## Loosely coupled updates

The matching Well-Architected best practice is SEC11-BP06. See the [framework mapping](cyber-resilience-framework-mapping.md#best-practice-ids) for the mapping table.

The purpose is to apply updates to dependencies and workflows in small steps that can be rolled back, so that when an update breaks, the impact stays within the repositories that took it in.

### Steps

1. In one repository, let only Renovate create update PRs. Do not run Dependabot version-update PRs alongside it. Keep Dependabot alerts enabled, as in step 4 of [Defending at intake](#defending-at-intake).
2. Pin calls to the Hub's reusable workflows to a 40-character SHA and add a version comment (`# <tag>`). With the version comment, Renovate can update the SHA and the tag together.
3. When a Hub workflow breaks, open a PR that returns the reference SHA to the previous one and merge it once CI passes. This can be done without waiting for a Hub fix. Only the repositories that updated their reference to the broken version stop; repositories that kept the previous SHA are not affected. Confirm the rollback by the caller job finishing successfully.
4. Do not automerge updates that reference Hub workflows (`hub_reusable_workflow` in the Policy_File `automerge.exclude`). If they were automerged, a change to a verification gate would reach every Spoke automatically after the Cooldown.
5. Update Lambda functions with a gradual deployment and automatic rollback on an alarm. The reference is `EventTransformerLambda` in this repository's [`templates/event-driven.yaml`](../../templates/event-driven.yaml). It has `AutoPublishAlias: live`, a `DeploymentPreference` of `Canary10Percent5Minutes`, a CloudWatch alarm on the alias's error count, and `UpdateRuntimeOn: FunctionUpdate` in `RuntimeManagementConfig`. The composition was confirmed only by reading the template; the template was not deployed, and traffic shifting and rollback were not observed. Confirmation in a real deployment belongs to the second pillar.
6. For upgrading self-managed ONTAP, follow the [ONTAP upgrade procedure](../ontap-native/ontap-upgrade-for-security-advisories.md).

### Policy_File keys and a pinned-reference example

The matching keys are `automerge.exclude`, `automerge.include`, and `automerge.enabled_repositories`. A caller workflow example follows. Replace `<40-character SHA>` with the value at the time the Hub publishes the reusable workflow, and `policy-ref` with a 40-character SHA of this repository.

```yaml
jobs:
  supply-chain:
    uses: Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/.github/workflows/cooldown-pinning-check.yml@<40-character SHA> # <tag>
    with:
      policy-ref: <40-character SHA of this repository>
    permissions:
      contents: read
```

In the configuration that uses `policy-ref`, the verification itself runs from a checkout of this repository. If this repository cannot be reached, or the commit named by `policy-ref` is gone, the calling job stops.

### Choosing a tool

There are three options for the bot that creates updates. No ranking is given.

| Option | Suited to | Trade-offs |
|---|---|---|
| Renovate (adopted) | Distributing a shared preset from one place on the Hub and aligning the Cooldown and the automerge scope across several repositories | The execution platform (for example, a Renovate GitHub App) has to be operated. Running it alongside Dependabot version-update PRs duplicates PRs |
| Dependabot version updates | Staying with built-in GitHub features and not adding an execution platform | This programme's gates and Policy_File assume Renovate settings, so the same checks have to be provided separately if you use it. This programme does not provide a way to distribute shared settings from the Hub |
| Update by hand | A person wants to see every update; few repositories and dependencies | Effort grows with the number of updates, and omissions are easier to make |

## Automerge scope

Only an update that meets all four conditions is automerged: (a) a dependency declared for development, or a GitHub Actions update; (b) a patch update; (c) the Cooldown has elapsed; and (d) every CI check required by branch protection has passed. The assumption is that, in one repository, only Renovate creates update PRs; do not run it alongside Dependabot version-update PRs.

### In scope and out of scope

| Kind of update | Automerge | Reason |
|---|---|---|
| Patch updates to npm `devDependencies` | In scope | A dependency declared for development, and a patch update |
| Patch updates to GitHub Actions (except Hub reusable workflows) | In scope | A patch update |
| Updates to runtime dependencies | Out of scope | They enter the deployed artifact. The PR is created and a person reviews it |
| Minor and major updates | Out of scope | They can include behavior changes. The PR stays open |
| Digest-only updates | Out of scope | The version number does not change, so it cannot be told apart from a patch |
| Dependencies whose development or runtime role cannot be determined (for example, Python `requirements-dev.txt`) | Out of scope | Whether Renovate's `pip_requirements` manager tells development files from the file name has not been checked (hypothesis). Anything that cannot be determined is out of scope |
| Vulnerability-fix PRs | Out of scope | They can be disguised malicious releases. A human approving review is required |
| Updates to Hub reusable workflows | Out of scope | To keep a change to a verification gate from reaching every Spoke automatically |

### Where automerge actually applies

The preset allows automerge for two kinds of update only, so depending on how a repository is built, automerge hardly applies.

| Repository composition | Applies | Notes |
|---|---|---|
| npm `devDependencies` | Applies to patch updates | Minor and above stop at the PR |
| GitHub Actions | Applies to patch updates | Hub reusable workflows are excluded |
| Mostly Python (`requirements.txt`, `pyproject.toml`) | Does not apply | Development or runtime role cannot be determined, so these are out of scope. Do not expect automerge in a Python-centered repository |
| AWS CDK (npm `dependencies`) | Does not apply | Treated as runtime dependencies |
| Container image digests | Does not apply | Digest-only updates are out of scope |

### Conditions and steps for enabling it

Automerge starts disabled in every repository. The Policy_File `automerge.enabled_repositories` starts as an empty array, and repositories are added one by one after they have been confirmed.

1. A maintainer checks that the repository's default-branch ruleset has at least one required CI check. Without any required check, GitHub's automerge can merge without waiting for tests to finish. This is a design understanding based on Renovate's documentation and has not been confirmed by running it.
2. A maintainer writes the number of required checks per repository into `docs/agent/automerge-required-checks.json` by hand (`{"required_checks": {"<owner>/<name>": count}}`). It is not replaced automatically from the Aggregator's output. The maintainer creates this file when the first repository is ready to be enabled. The gate fails unless each repository in `enabled_repositories` has a count of 1 or more.
3. Add the repository to the Policy_File `automerge.enabled_repositories`.
4. In that repository's `renovate.json`, add the automerge preset (`renovate/supply-chain-automerge`) to `extends`, after the main preset. If a repository that is not in `enabled_repositories` references this preset, the gate fails.
5. Last, enable `allow_auto_merge` on the repository.

### Choosing an approach

There are three options for the automerge approach. No ranking is given.

| Approach | Suited to | Trade-offs |
|---|---|---|
| Renovate `platformAutomerge` (GitHub's automerge; adopted) | Having GitHub wait for the required checks to finish | In a repository with no required checks, the merge can be immediate (hypothesis). It depends on the ruleset settings, so it stays disabled until the settings have been checked |
| Renovate's own merge (`platformAutomerge: false`) | Not wanting to enable GitHub's automerge feature | The merge is delayed until Renovate's next run. Renovate judges the status checks |
| No automerge | A person wants to see every update | Review effort grows in proportion to the number of updates |

## Operating VEX

VEX records, with a basis, a judgment such as "this vulnerability does not affect" a given version of a component. The format is [OpenVEX](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md) v0.2.0, and the files live in the repository's `.vex/` directory.

### Rules

- One VEX document holds exactly one statement. The author of a judgment is recorded as a role name (VEX_Reviewer), not as a personal name or email address.
- A judgment drafted by an AI agent is an auxiliary signal, not a final judgment. Record, for each judgment, that an AI agent drafted it.
- A judgment that has not been approved is not used as a reason to hold back an Issue. Approved means the PR containing a VEX_Reviewer's review was merged to the default branch.
- If the component version a judgment covers differs from the Finding's version, the judgment is not used. When the component version changes, the judgment no longer applies.
- Only the Aggregator reads `.vex/`. VEX is not passed to the layer B scanner.
- A judgment whose vulnerability identifier is `MAL-` is not used to hold back an Issue, whether its status is `not_affected` or `fixed`. A malicious package cannot be excluded with VEX.
- `not_affected` is a record that "there is no impact". It is not an acceptance of the risk of leaving something unfixed. If you accept a risk and do not fix it, keep that record somewhere other than VEX, such as an Issue comment.
- A judgment that rests on whether code runs, such as `vulnerable_code_not_in_execute_path`, carries evidence (the analysis method and the call path). A judgment without evidence is not approved.

### Constraint for single-owner repositories

VEX approval is enforced with the following ruleset. The required approval count is 0, review by Code Owners is required, and CODEOWNERS covers `/.vex/` only. A review by a VEX_Reviewer (a human) other than the PR author is the condition for merging a PR that changes `.vex/`. An AI agent's review is not counted toward this condition. A PR that does not touch `.vex/` can be merged without approval.

In a personal-account repository with a single owner, these constraints apply.

- Only an arrangement in which an AI agent with an identity separate from the owner's (a GitHub App or a dedicated account) creates the VEX PR and the owner approves it meets this condition.
- An arrangement in which the owner creates the VEX PR does not meet this condition. The owner cannot approve their own PR, so the merge condition cannot be met.
- Do not start this arrangement until the separate identity exists. Providing the identity is a maintainer's task; an AI agent does not stand in for it.

Verify the setting in two ways: confirm that a `.vex/` PR created by the owner cannot be merged, and that a PR that does not touch `.vex/` can be merged.

### Monthly review

A wrong `not_affected` keeps the Issue for that (repository, vulnerability, version) combination held back. The impact is limited to that combination, and when the component version changes the judgment stops applying. Once a month, compare the basis of each approved VEX document with the component version. If you find an error, a VEX_Reviewer approves and merges a PR that deletes that VEX document (or changes it to `affected`). Confirm by checking that the Issue for that Finding is reopened or opened in the next Aggregator run.

## Verifying provenance

A provenance attestation (Provenance_Attestation) lets a consumer verify which commit and which workflow produced a release artifact. The target level is SLSA Build L2, where each repository uses `actions/attest` in its own workflow.

### Producer-side steps

1. Add `actions/attest` (pinned by SHA) to the release workflow and create one attestation per artifact. The job permissions are `id-token: write`, `attestations: write`, and `contents: read`.
2. Place the publish step after the provenance step and connect them with `needs`. If creating the attestation fails, do not publish the release.
3. Attach the attestation bundle to the release as `*.sigstore.json`. Attach it to the release SBOM as well.
4. Building and attesting inside a Hub reusable workflow corresponds to L3. This programme does not adopt L3, because a Hub failure would then also affect releases and the set of repositories that could adopt it would be narrower still. L3 is the option that gives isolation between runs.

As checked on 2026-11-10, none of the Target_Repositories attached release artifacts, published packages to a public registry, or pushed images. Whether GitHub Packages holds any package could not be checked, because the `read:packages` permission was not available. Observability-integrations has 6 releases with 0 attached files, and it becomes the first adopter once it starts attaching files. When a repository starts publishing packages to a public registry, re-read that registry's documentation and decide the publication criteria then.

### Consumer verification steps

```bash
gh attestation verify <artifact file> \
  --repo <owner>/<name> \
  --signer-workflow <owner>/<name>/.github/workflows/<file>
```

1. Three values are compared: the artifact digest (the command computes it from the file), the expected repository (`--repo`), and the expected workflow file path (`--signer-workflow`). At L2, the expected workflow is each repository's own.
2. Success is an exit code of 0. The wording of the output can change between versions, so the exit code is authoritative.
3. Verification fails when there is no attestation, the digest does not match, or the repository or workflow differs from what is expected. Do not take in an artifact that fails.

### Verifying the distribution of pinned tools

The tools used to generate and scan SBOMs are pinned to an exact version and digest. Verify that a pinned release is genuine in this order.

1. Check whether the release is an immutable release. If it is not, treat its assets as something that can be replaced later.
2. If `checksums.txt` exists, compare it with the hash of the file you fetched.
3. If a sigstore bundle exists, verify the signature.
4. If a SLSA provenance exists, verify the expected repository and workflow.
5. If none exists, rely only on the digest pin and record that distribution verification was skipped.

The trade-off is that the tools used for verification (cosign, slsa-verifier, and so on) are themselves something more to pin and update.

## Response targets

A Response_Target is a "target". Until it has been measured in operation, it is not called an SLO. The values live in the Policy_File `response_target`, and the numbers in this guide match the Policy_File.

| Item | Value | Interval it applies to |
|---|---|---|
| Detection | <!-- policy:response_target.detect_hours -->24 hours | From the starting point to Issue creation |
| Fix (KEV-listed, or a malicious package) | <!-- policy:response_target.fix_days_kev_or_malicious -->7 days | From Issue creation to closing |
| Fix (CVSS severity High or above, not KEV-listed, and not a malicious package) | <!-- policy:response_target.fix_days_high -->14 days (reference value) | From Issue creation to closing |

The <!-- policy:response_target.fix_days_high -->14 days for High and above (not KEV-listed) is a reference value; the pilot decides whether to keep it or return to 30 days. A Finding that is both KEV-listed and High or above gets 7 days. If the vulnerability behind an open High-or-above Issue is later added to KEV, the deadline is updated to the earlier of the existing deadline and 7 days after the run that detected the listing.

The starting point is the later of two times. The first is when the Finding first met the Opening_Threshold (the advisory's publication time for CVSS, 00:00:00 UTC on the KEV listing date when only KEV qualifies it, and the feed entry's publication time for a malicious package). The second is the time of the run in which the Aggregator first observed that component version. An Issue whose starting point cannot be obtained is recorded with the starting point as "unknown", left out of the detection results, and the number left out is written to the run result.

The 24-hour detection target is this programme's internal target. It is not the deadline for the early warning to the authorities (within 24 hours) that the EU Cyber Resilience Act requires of manufacturers for actively exploited vulnerabilities ([Cyber Resilience Act - Reporting obligations](https://digital-strategy.ec.europa.eu/en/policies/cra-reporting)).

### Replacing the values with your own

1. Open a PR that rewrites the three values in the Policy_File `response_target` (`detect_hours`, `fix_days_kev_or_malicious`, `fix_days_high`) to your own targets. The values are positive integers; the parser rejects negative or non-integer values.
2. In the same PR, rewrite the number right after each marker that starts with `policy:` (an HTML comment) in this guide to the same value. Change both the Japanese and English versions.
3. The `guide-values` gate checks that the numbers right after the markers in this guide match the Policy_File and, on a mismatch, fails with the value and its location. This gate is planned and is not implemented as of this guide. The match was checked by hand.
4. After the change, see in the next monthly review (the section [Using actual results in the PDCA cycle](#using-actual-results-in-the-pdca-cycle)) how the results come out against the new targets.

### Comparison with other deadlines

As material for replacing the reference values of the Response_Target, the deadlines of public documents are summarized. These deadlines are imposed by each document on the organizations or scheme participants it covers, and apply neither to this programme nor to a Service_Owner. They are not a judgment about which value is correct. The source of each row is given by the number in the Source column, which refers to the [References](#references).

| How it divides cases | Example deadlines | Starting point | Who it applies to | Source |
|---|---|---|---|---|
| Public examples (2) that divide by CVSS base score or vendor severity | 14 days for High and above (CVSS 7 or higher) | Release of the update | Organizations that take part in a certification or evaluation scheme | [27], [28] |
| A public directive that divides by four variables: whether exposed, KEV listing, whether an attacker can automate, and technical impact (CVSS is not used) | 3 days, 14 days, 60 days, or the next system update | The earlier of the KEV addition and identification on the asset | The agencies the directive covers | [29] |

In this programme, the starting point of a fix is Issue creation, and the 24-hour detection target comes before it. The deadlines in the table therefore cannot be compared from the same starting point. The 7 days for KEV listing lies between the 3 days and 14 days in the second row.

The Response_Target is governance guidance, not a legal, compliance, or regulatory judgment.

## Using actual results in the PDCA cycle

For each Issue, the Aggregator records the starting point, detection, creation, and closing times, and the reason for closing (resolved by a fix, `not_affected` by VEX, `withdrawn`, `feed_version_delisted`). The result for fixes covers only Issues resolved by a fix, and is viewed in three intervals.

- From detection to Issue creation
- From Issue creation to the fix PR
- From the PR to the merge

Vulnerability-fix PRs are not automerged, so waiting for human review can account for most of the fix time. The split into three is there to show where the delay is.

### Monthly review steps

1. Check: In the Aggregator's run results, check, per repository, the number of Issues left open past their fix deadline and the number of Issues opened in the run whose detection time exceeded 24 hours. Also look at the number left out because the starting point was unknown.
2. Check: See in which of the three intervals the delay lies. If it is review waiting, suspect how people are assigned; if it is detection to creation, suspect the Aggregator's interval and feed fetch failures.
3. Act: When deadline overruns continue, decide whether to change the Response_Target to fit reality or to fix the cause of the delay. If the Cooldown is the cause of the delayed fixes, review the Cooldown value.
4. Act: When you change a value, follow [Replacing the values with your own](#replacing-the-values-with-your-own) and fix the Policy_File and the numbers in this guide in the same PR.
5. Check the current version of references that carry a version or date: the Well-Architected Framework, SLSA, OpenVEX, the EPSS model, and Renovate.
6. Review the approved VEX documents ([Operating VEX](#monthly-review)).

Check corresponds to Well-Architected OPS09-BP01 (measure operations goals with metrics), and Act corresponds to OPS11-BP02 (identify preventive actions through post-incident analysis). See the [framework mapping](cyber-resilience-framework-mapping.md#best-practice-ids) for the mapping table; it is not copied here.

### Items to confirm in the pilot

For the first 14 calendar days, the programme applies to two repositories only. The false-positive rate is the number of Issues that a VEX_Reviewer judged `not_affected` by the end of the pilot, divided by the number of Issues opened. The number of Issues not yet judged is recorded separately. If no Issue is opened, record the rate as not calculable, and record with the reason whether to extend by 14 calendar days or move to the next stage. At the same time, decide whether to keep the fix target for High and above at 14 days or return to 30 days.

## Relationship to Well-Architected

The correspondence between this guide and Well-Architected best-practice IDs is not the result of an AWS Well-Architected review, and it is not an AWS endorsement. It reflects a reading of the best-practice pages and a judgment that the components address the same topic. The mapping table is placed only in the [framework mapping](cyber-resilience-framework-mapping.md#best-practice-ids), and this guide does not copy it. The version referred to is v13 (2024-11-06).

A workload owner can review their own workload with the [AWS Well-Architected Tool](https://aws.amazon.com/well-architected-tool/) and record decisions and improvements. The mapping to NIST CSF 2.0 is in a [section](cyber-resilience-framework-mapping.md#mapping-pdca-and-accountability-to-csf-20) of the same mapping, and it is not a NIST endorsement. Both mappings are governance guidance, not legal, compliance, or regulatory judgments.

## References

The documents this guide relies on are listed in this order: name (the original title given by the publisher), publisher, publication date and version, URL, and the date checked (the day the content of that URL was confirmed). Where no date is shown, that is stated. Names are kept in the original title in both the Japanese and English versions. The numbers match the `[n]` marks in the text. A document cited with `[E-nnn]` has the same URL in the source field of [evidence-ledger.json](../agent/evidence-ledger.json).

| No. | Name | Publisher | Date and version | URL | Date checked |
|---|---|---|---|---|---|
| 1 | Minimum Release Age | Renovate | No date shown | [docs.renovatebot.com](https://docs.renovatebot.com/key-concepts/minimum-release-age/) | 2026-11-13 |
| 2 | Configuration Options | Renovate | No date shown | [docs.renovatebot.com](https://docs.renovatebot.com/configuration-options/) | 2026-11-13 |
| 3 | config (npm CLI v11) | npm | v11 | [docs.npmjs.com](https://docs.npmjs.com/cli/v11/using-npm/config) | 2026-11-13 |
| 4 | OpenVEX Specification | OpenVEX | v0.2.0 | [github.com/openvex](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md) | 2026-11-10 |
| 5 | Using artifact attestations | GitHub | No date shown | [docs.github.com](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations) | 2026-11-10 |
| 6 | gh attestation verify | GitHub | No date shown | [cli.github.com](https://cli.github.com/manual/gh_attestation_verify) | 2026-11-10 |
| 7 | Build: Track Basics | OpenSSF SLSA | v1.2 | [slsa.dev](https://slsa.dev/spec/v1.2/build-track-basics) | 2026-11-12 |
| 8 | REST API endpoints for software bill of materials (SBOM) | GitHub | API version 2026-03-10 | [docs.github.com](https://docs.github.com/en/rest/dependency-graph/sboms) | 2026-11-13 |
| 9 | Exporting SBOMs with Amazon Inspector | AWS | No date shown | [docs.aws.amazon.com](https://docs.aws.amazon.com/inspector/latest/user/sbom-export.html) | 2026-11-13 |
| 10 | Amazon Inspector integration with AWS Security Hub CSPM | AWS | No date shown | [docs.aws.amazon.com](https://docs.aws.amazon.com/inspector/latest/user/securityhub-integration.html) | 2026-11-13 |
| 11 | Amazon Inspector Lambda standard scanning | AWS | No date shown | [docs.aws.amazon.com](https://docs.aws.amazon.com/inspector/latest/user/scanning_resources_lambda.html) | 2026-11-13 |
| 12 | Scanning AWS Lambda functions with Amazon Inspector | AWS | No date shown | [docs.aws.amazon.com](https://docs.aws.amazon.com/inspector/latest/user/scanning-lambda.html) | 2026-11-13 |
| 13 | AWS Security Hub FAQs | AWS | No date shown | [aws.amazon.com](https://aws.amazon.com/security-hub/faqs/) | 2026-11-13 |
| 14 | Software bill of materials (AWS Security Hub User Guide) | AWS | No date shown | [docs.aws.amazon.com](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-v2-sbom.html) | 2026-11-13 |
| 15 | AWS Security Hub now provides an SBOM inventory for your compute resources | AWS | 2026-11-06 | [aws.amazon.com](https://aws.amazon.com/about-aws/whats-new/2026/11/security-hub-sbom-inventory/) | 2026-11-12 |
| 16 | AWS Security Hub Pricing | AWS | No date shown | [aws.amazon.com](https://aws.amazon.com/security-hub/pricing/) | 2026-11-12 |
| 17 | GetSoftwareV2 (AWS Security Hub API Reference) | AWS | No date shown | [docs.aws.amazon.com](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetSoftwareV2.html) | 2026-11-13 |
| 18 | AWS Well-Architected Framework | AWS | v13 (2024-11-06) | [docs.aws.amazon.com](https://docs.aws.amazon.com/wellarchitected/latest/framework/welcome.html) | 2026-11-13 |
| 19 | What is AWS Well-Architected? | AWS | 2026-10-01 (the page's Last updated) | [docs.aws.amazon.com](https://docs.aws.amazon.com/wellarchitected/latest/userguide/well-architected.html) | 2026-11-10 |
| 20 | Well-architected best practices for software supply chain security | AWS Security Blog | The publication date could not be obtained | [aws.amazon.com](https://aws.amazon.com/blogs/security/well-architected-best-practices-for-software-supply-chain-security/) | 2026-11-10 |
| 21 | OpenSSF Malicious Packages | OpenSSF | No date shown | [github.com/ossf](https://github.com/ossf/malicious-packages) | 2026-11-10 |
| 22 | OSV.dev Data Sources | OSV.dev | No date shown | [google.github.io](https://google.github.io/osv.dev/data/) | 2026-11-10 |
| 23 | Known Exploited Vulnerabilities Catalog | CISA | catalogVersion 2026.11.09 | [cisa.gov](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | 2026-11-10 |
| 24 | GET /epss (FIRST.Org REST API Documentation) | FIRST | The API is shown as BETA | [api.first.org](https://api.first.org/epss/) | 2026-11-12 |
| 25 | Cyber Resilience Act - Reporting obligations | European Commission | No date shown | [digital-strategy.ec.europa.eu](https://digital-strategy.ec.europa.eu/en/policies/cra-reporting) | 2026-11-10 |
| 26 | MCP Security Crisis: Systemic Design Flaws in AI Agent Infrastructure | Cloud Security Alliance (CSAI Foundation) | 2026-05-04 (research note; the document states that it was produced with AI assistance and has not had formal CSA review) | [labs.cloudsecurityalliance.org](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/05/CSA_research_note_MCP_security_crisis_20260504-csa-styled.pdf) | 2026-11-10 |
| 27 | ★3・★4要求事項・評価基準（Ver.1.1:2026年10月28日） (Japanese only) | METI | Ver 1.1, 2026-10-28 (evidence: documented) | [xlsx](https://www.meti.go.jp/policy/netsecurity/docs/scs/SCS-400-criteria-v1.1.xlsx) | 2026-11-12 |
| 28 | Cyber Essentials: Requirements for IT Infrastructure v3.3 | NCSC (UK National Cyber Security Centre) | v3.3, April 2026 (evidence: documented; the section read is Security Update Management) | [ncsc.gov.uk](https://www.ncsc.gov.uk/files/cyber-essentials-requirements-for-it-infrastructure-v3-3.pdf) | 2026-11-13 |
| 29 | BOD 26-04: Prioritizing Security Updates Based on Risk | CISA | 2026-06-10 (evidence: documented; Table 1 is an image, read as an image on 2026-11-12) | [cisa.gov](https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk) | 2026-11-13 |

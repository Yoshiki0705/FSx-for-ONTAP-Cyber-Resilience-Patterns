# Supply-Chain Adoption Guide (Pillar 1)

> **Summary**: This guide shows how to adopt the first pillar, software supply-chain visibility and response, across your own repositories. For each of the four areas (inventory, exploitability-based detection and prioritization, defense at intake, and loosely coupled updates) it gives the purpose, numbered steps, the matching policy file keys, a pinned-reference example, and how to choose a tool. The numbers match the values in [`docs/agent/supply-chain-policy.json`](../agent/supply-chain-policy.json) (the policy file). The state at the time of writing, such as the Hub-side settings that are not yet created, is collected in the section [Status](#status).

## Intended readers

Two kinds of readers are expected. One is a service owner role: a partner or SI, a system owner, or an application owner. The other is an AI agent that works in place of those roles. Both work within the policy and the approvals that the repository maintainer has set. An AI agent follows three rules.

- It drafts judgments only. It does not approve a VEX statement, enable automerge, or change a response-time target without a human's approval.
- It reads numbers from the [policy file](../agent/supply-chain-policy.json) and does not copy the values in this guide.
- An `[E-nnn]` next to a "cannot" or "is not listed" statement is a registration number in [evidence-ledger.json](../agent/evidence-ledger.json). It does not add a claim that is not registered there.

The terms below are used under these names from here on.

| Term | Meaning |
|---|---|
| Policy file | A JSON file that holds thresholds, waiting periods, the automerge scope, the target repositories, and the response-time targets (named `Policy_File` in the code). The reference for the numbers in this guide |
| Maintainer | The person who changes the settings of the target repositories and gives approvals |
| Owner | The account that owns a repository on GitHub. For a repository under a personal account, the owner is the same person as the maintainer |
| Service owner | The party that provides a service to end users and sets its SLA/SLO/SLI and RTO/RPO (the role of the party that adopts this guide) |
| Artifact consumer | The party that takes in a release artifact |
| Hub | The repository that holds the reusable workflows and the Renovate shared preset: [FSx-for-ONTAP-Adoption-Playbook](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook) |
| Spoke | A target repository other than the Hub. It references the reusable workflows and the Renovate shared preset that the Hub distributes |
| Target repositories | The 12 repositories listed in the policy file `target_repositories`. They include this repository and the Hub |
| Aggregation job | The scheduled job on the Hub that matches each repository's SBOM against vulnerability data and opens Issues in the repository (named `Aggregator` in the code) |
| Finding | The detection result that the aggregation job produces for one combination of repository, vulnerability, and component version. It is the unit on which the decision to open an Issue is made |
| Watchdog | A mechanism that runs as a workflow separate from the aggregation job and checks that the aggregation job's newest run result is not out of date and that its recent runs did not fail |
| Opening condition | The condition for opening an Issue: CVSS severity High or above, a CISA KEV listing, or a malicious package |
| VEX | Vulnerability Exploitability eXchange. A format that records, with a basis and in a machine-readable form, whether a vulnerability affects a given version of a component. This guide uses OpenVEX |
| VEX approver | The human role that approves VEX statements. The policy file `vex.approver_role` has the value `VEX_Reviewer` |
| Response-time target | The target time for detection and fixing. Not called an SLO |
| Cooldown | The waiting period before a freshly published version is taken in |
| Verification gate (gate) | A script that checks that settings match the policy file and fails with exit code 1 on a violation. Run it with `make check-supply-chain` |
| Pilot | The period in which the detector's errors are checked on the first two repositories (this repository and the Hub). It is counted from the run in which the aggregation job first produced the findings list for both. The default is 14 calendar days; when fewer than 20 Issues have been opened, it can be extended by 14 calendar days, up to 2 times (42 calendar days in total). The result decides the thresholds and the observation period for the next group of repositories (a batch). The items to confirm are in [Items to confirm in the pilot](#items-to-confirm-in-the-pilot) |
| Batch | A group of repositories to which the controls are applied, one group after another, after the pilot, for the remaining 10 repositories. There are 4 groups of 3, 3, 3 and 1 repositories, and the default observation period of each batch is 7 calendar days |
| Evidence label | One of four words: `documented` (the relevant part of the source was read), `verified` (measured at least once), `hypothesis` (this project's interpretation), `open` (not confirmed) |
| Detection starting point | The time from which the detection target is measured. Defined in the section [Response targets](#response-targets) |

The three pillars as a whole are described in [the overall plan for the three pillars](cyber-resilience-programme.md). This guide covers the adoption of the first pillar only.

## Status

The state as of 2026-11-15 is as follows. "Not created", "not merged" and "not confirmed" in the text refer to this section.

- The Hub's main has the workflows `supply-chain-aggregator` (every 6 hours), `supply-chain-watchdog`, `vex-validate`, and `sbom-generate` published and enabled (checked on 2026-11-15). Whether the Renovate shared preset is published, and whether the Hub has a tag, have not been checked. The references in this guide are the placeholders `<40-character SHA>` and `<tag>`; replace them once they are checked.
- The Hub's Aggregator fails on every run. The repository variables (`SUPPLY_CHAIN_APP_CLIENT_ID`, `SUPPLY_CHAIN_POLICY_REF`), the secret (`SUPPLY_CHAIN_APP_PRIVATE_KEY`), and the `supply-chain-runs` branch are not created yet. This is by design, and creating them is the maintainer's work. The Hub's watchdog still had the 12-hour limit when checked. Hub PR #383 (draft, not merged) contains a sync of the copy of `tools/supply_chain/`, the 8-hour limit, `--policy-file`, `--chain-ack`, `--report-file`, `chain_to_previous`, and the maintainer's procedure. The PR's checks were still running when checked. Until the PR is merged, the run results of the Hub workflows and the real-environment behaviour of `chain_to_previous` have not been checked.
- The decisions for opening Issues, for VEX exclusion, and for the watchdog are in this repository, in `solutions/supply-chain/`, as pure functions with unit tests.
- The verification gates run with `make check-supply-chain`. One of them, `guide-values`, checks that the numbers in this guide match the policy file.
- The check that a `.vex/` change was approved by a human other than its author runs on the Hub side. `vex-validate` is published on the Hub, but that it reads `.vex/` and checks approval by someone other than the author has not been confirmed by running it (open).
- Three things have not been confirmed by running them: that the reference form of the Renovate shared preset (`github>…#<tag>`) resolves in Renovate; that the Cooldown for GitHub Actions guards against a moved tag (it is not expected to; hypothesis); and that a Lambda canary deployment shifts traffic and rolls back on an alarm.
- The weekly check of the watchdog (`watchdog_cli`) and the recovery of a forked record chain (`chain_recovery`) are in `solutions/supply-chain/` of this repository, and their steps were run on 2026-11-15 in a throwaway directory. What was confirmed: whether `PYTHONPATH` is needed, running from other working directories, reading the Hub's real workflow listing (`gh api`), and detecting, registering, and reconnecting a fork. Starting from launchd was also checked the same day, up to this point: a throwaway plist was loaded with `launchctl bootstrap` and started with `kickstart`, `--overdue-check` returned exit code 1 inside the job, and `osascript display notification` was called with exit code 0. What was not confirmed: that the notification banner appeared on screen, a `StartCalendarInterval` run after waking from sleep, fetching the `supply-chain-runs` branch (the branch is not created yet), and the Hub's aggregation job and watchdog reading the ledger. The weekly check stops at step 2 until the `supply-chain-runs` branch is created. While it is stopped, nothing notices that the Hub's watchdog has stopped.
- The procedures for the second and third pillars are not published.

## The four areas and scope

| Area | What it does | Main parts |
|---|---|---|
| Inventory | Keeps a machine-readable record of what is where | SBOMs, infrastructure component ledger, agent component record |
| Detection and prioritization | Turns exploited vulnerabilities and malicious packages into Issues first | Aggregation job, OpenVEX |
| Defense at intake | Keeps freshly published versions and unpinned references out | Renovate shared preset, verification gates, provenance attestation |
| Loosely coupled updates | Applies updates in small steps that can be rolled back | Automerge policy, Lambda canary deployment reference |

### Out of scope and the limits of pinning

Out of scope: no AIBOM / ML-BOM format is produced, and the record of agent components stays a standalone JSON file outside the SBOM. Digest pinning for .NET (NuGet), Terraform, and Dockerfile `FROM` lines is not checked by the first pillar. It is recorded as a subject for a later stage.

Pinning has limits. The three points below remain risks even when a reference looks pinned.

- Pinning a version does not cover changes to the tool definitions an MCP server returns (hypothesis; this is this project's inference, not a vendor statement). Detecting tool-definition changes is not part of the first pillar's gates. A Cloud Security Alliance research note recommends inventorying the MCP servers in use, pinning versions, and detecting definition changes. The note states that it was itself produced with AI assistance and has not had formal review [G26].
- A top-level pin (`npx -y <pkg>@<x.y.z>` or `image@sha256:…`) does not pin transitive dependencies. Pinning the whole dependency tree needs a lock file.
- An image pinned by digest does not take in security updates on its own. Updates arrive as Renovate PRs that a human reviews.

The Cooldown of <!-- policy:cooldown_days.default -->3 days is a conventional value, not a measured one. No external basis has been found for the <!-- policy:cooldown_days.major -->7 days for major updates either. The pilot will review both by looking at the number of fixes that the waiting period delayed ([Basis and limits of the Cooldown values](#basis-and-limits-of-the-cooldown-values)).

Amazon Inspector's AI inventory finds self-hosted AI frameworks in EC2 instances and ECR images; the AWS Security Hub FAQ describes it [G13]. It has a different subject from the first pillar's agent component record, which counts files in repositories. It can complement the view of running resources, but the user guide has not been read, so check it before relying on it.

### Official configuration examples rewritten in pinned form

MCP client configuration examples are often written with `uvx <pkg>` or `npx -y <pkg>` without a version, or with an image that has only a tag. The pinned form is shown below. `<x.y.z>` and `<64 digits>` are placeholders; decide them after checking the official release. The configuration file name and key names differ by client, so check each client's documentation. This guide has not checked the documentation of the individual clients.

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

A remote server specified only by `url` is recorded as "not applicable" rather than as a pinning target. An MCP server that is recommended by name only (no declaration file) needs a declaration file. If you do not add one, note "version not pinned" in the file that makes the recommendation.

## Inventory

The matching Well-Architected best practices are SEC11-BP02 and SEC11-BP05. The mapping table is in the [framework mapping](cyber-resilience-framework-mapping.md#best-practice-ids) and is not copied here.

The purpose is to be able to answer, when a vulnerability is published, "which version in which of my repositories is affected" without searching by hand.

### Steps

1. Prepare a policy file for your own repositories. Copy this repository's `docs/agent/supply-chain-policy.json` and rewrite `target_repositories` to the list of your repositories. This repository's list has 12 entries, and the 4 entries in `excluded_repositories` (2 upstream repositories of the AWS Baseline Environment on AWS and their 2 forks) are not scanned.
2. Enable layer A, the GitHub dependency graph. The aggregation job fetches the SBOM through the API. GitHub announced that its synchronous SBOM export API is not accessible after 2026-11-13 (checked 2026-11-13) [E-044][G8]. As of 2026-11-14, the response after the shutdown has not been checked. Use the asynchronous `generate-report` and `fetch-report` path.
3. For layer B (scanning in CI), call the Hub's `sbom-generate` from a caller workflow. Pin the reference to a 40-character SHA from the start. GitHub keeps the artifact `sbom-<commit-sha>` for 90 days. 90 days is the limit for public repositories; when you add a private repository, you can choose a retention of up to 400 days.
4. A repository that publishes releases attaches the SBOM of the commit that produced the release to the release. An attached SBOM is kept as long as the release. For a release without an attached SBOM, no SBOM remains after 90 days, and the composition is answered by rebuilding. A rebuilt SBOM may be made with different tool versions from those used at the time.
5. Record agent components (MCP servers, agent settings, installation steps) in `docs/agent/agent-components.json`, and bring the number of unpinned entries to 0.
6. ONTAP versions, Amazon FSx for NetApp ONTAP (FSx for ONTAP from here on) file systems, and the versions of the TrendAI and Deep Instinct agents are not put in an SBOM. A person records them in [`infrastructure-component-ledger.json`](../agent/infrastructure-component-ledger.json). An entry is listed for re-matching once more than 90 days have passed since the matching date (from day 91).

### policy file keys and a pinned-reference example

The matching keys are `target_repositories`, `excluded_repositories`, and `dependency_scope.non_production_paths` (paths excluded from the production-dependency decision; the initial values are `tests/` and `docs/`). A caller workflow example follows. Replace `<40-character SHA>` with a commit SHA on the Hub's default branch at the time the Hub publishes the reusable workflow. Write the `uses:` of a reusable workflow as a 40-character SHA from the start. GitHub documents that the ref of `jobs.<id>.uses` can be a SHA, and says a SHA is the safest choice for stability and security [G30]. A SHA can be taken from a commit on the Hub's default branch even before the Hub has a tag. A tag reference is allowed as a temporary measure only for the Renovate shared preset reference (`extends` in `renovate.json`; step 1 of [Defending at intake](#defending-at-intake)). As of 2026-11-14, whether the Hub has a tag has not been checked.

```yaml
jobs:
  sbom:
    uses: Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/.github/workflows/sbom-generate.yml@<40-character SHA> # <tag>
    permissions:
      contents: read
```

### Choosing among inventory options

Rows are options; columns are use, prerequisites, how cost is handled, and constraints. No ranking is given. The constraints of each option are written from the same two angles (what is not visible, what has to be prepared).

| Option | Use | Prerequisites | Cost handling | Constraints |
|---|---|---|---|---|
| Repository SBOM (layers A and B) | Match the dependencies, Actions, container images, and Lambda components that a repository declares against newly published vulnerabilities in the aggregation job, and open an Issue in the repository | The GitHub dependency graph (layer A) and a CI scan (layer B). Reusable workflow `sbom-generate` | No AWS charges. GitHub Actions run time | What enters after deployment (OS packages, agents installed by hand, libraries bundled by a runtime) is outside the record. CI has to be set up per repository |
| Amazon Inspector SBOM export (layer C) | Write the SBOM of the resources Inspector monitors to S3 as CycloneDX 1.4 / SPDX 2.3 JSON, and hand it to external tools or an audit record [G9] | Inspector enabled for the resource type. Policies on the destination S3 bucket and KMS key | Inspector scan charges (separate pricing, or Security Hub Essentials) plus S3 and KMS charges. The charge for the export itself has not been checked | The content is as of the time the export was requested; the service owner builds any periodic refresh. Agent-based EC2 Windows instances cannot be exported [E-052]. Inspector does not scan the AWS SDK bundled with the Lambda runtime [E-047], functions encrypted with a customer managed key [E-048], or functions not invoked or updated in the last 90 days [E-049] |
| SBOM inventory | Look up in the console or API which resources in the organization contain a given package and version (including data gathered into the home Region by cross-Region aggregation) | AWS Security Hub enabled per account and Region, and Inspector enabled per resource type. A delegated administrator to see the whole organization | Included in Essentials at no additional charge ([AWS What's New](https://aws.amazon.com/about-aws/whats-new/2026/11/security-hub-sbom-inventory/), checked 2026-11-12) [G15]. Essentials is priced per resource and includes Inspector standard scanning ([AWS Security Hub Pricing](https://aws.amazon.com/security-hub/pricing/), checked 2026-11-12) [G16]. It is not available where Security Hub is not enabled ([Security Hub User Guide](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-v2-sbom.html), checked 2026-11-13) [G14]. Unit prices are not given | The response has only name, version, type, and count, with no purl, so it cannot be matched directly against a repository SBOM [E-053]. FSx for ONTAP and ONTAP are not expected to be listed (hypothesis) [E-054]. A new SBOM can take hours to appear. The user guide and API reference do not describe export as SPDX or CycloneDX (this does not say export is impossible; this is open) |
| Infrastructure component ledger | Match ONTAP versions, FSx for ONTAP file systems, and the versions of the TrendAI and Deep Instinct agents against NetApp and AWS security advisories | A procedure in which a person matches and records. Listed for re-matching once more than 90 days have passed since the matching date | No AWS charges. The labor of matching | Not a machine-readable SBOM; matching is a human procedure (semi-automatic matching with RSS 2.0 as the source, with a person confirming). Changes after the matching date are not reflected until the next matching |

The steps for choosing are as follows.

1. Decide whether the subject is what a repository declares, a deployed resource, or the storage and agent base.
2. For what a repository declares, use layers A and B.
3. For deployed resources, when you want to look up across the organization where a package is installed and AWS Security Hub is enabled, use SBOM inventory.
4. For deployed resources, when you want to hand the SBOM to outside parties in a machine-readable form, or when Security Hub is not enabled, use layer C.
5. Record ONTAP, FSx for ONTAP, and the agents in the infrastructure component ledger.
6. If more than one applies, use them together. For example, export with layer C the SBOM of a resource found in SBOM inventory and match it by purl.

Within the first pillar, this project does not enable Amazon Inspector or AWS Security Hub and takes no action that incurs charges. Enabling them and estimating the cost belong to the second pillar. If you use them, check enabling and cost yourself.

### Choosing an SBOM generation tool

Use tools from the same lineage for generation and scanning. Decide the pair to adopt by measuring missed findings in the pilot.

| Tool | Suited to | Trade-offs |
|---|---|---|
| Trivy alone (Trivy generates and scans) | Entrusting generation and scanning to one lineage | One distribution incident affects both generation and scanning. The default exit code is 0 even when findings exist, so set `--exit-code` explicitly. That it does not report `MAL-` is a hypothesis (not run to confirm) |
| Syft (generate) + Grype (scan) | Matching generation and scanning as a pair from the same lineage | The versions of two tools have to be pinned and updated. Syft's `-o spdx-json` emits SPDX 3.0 by default, so specify `spdx-json@2.3`. Grype's handling of SBOM input has not been read (open) |
| Syft (generate) + Trivy (scan) | Handling both repositories and images with one scanner | Trivy's documentation warns that SBOMs made by other tools can lead to inaccurate detection. The lineages differ and findings can be missed, so measure missed findings in the pilot if you choose it |
| OSV-Scanner | Using the OSV database directly; repositories centered on lock files | Its handling of image scanning has not been read (open) |
| Layer A only | Not adding any extra tool | Limited to the declaration files GitHub reads. What lies outside that range is not included |

Pin tools to an exact version number and an image `sha256:` digest. Decide the version and digest after checking the official release. How to verify the distribution of a pinned tool is in the section [Verifying provenance](#verifying-provenance).

## Detection and prioritization

The matching Well-Architected best practices are SEC11-BP02 and SEC11-BP05. See the [framework mapping](cyber-resilience-framework-mapping.md#best-practice-ids) for the mapping table.

The purpose is to turn exploited vulnerabilities and malicious packages into Issues first. If you order only by CVSS severity, vulnerabilities rated Medium or below that have evidence of exploitation are pushed back.

### Steps

1. Check `opening_threshold` in the policy file. By default an Issue is opened when any of three conditions is met: CVSS severity `HIGH` or above, a KEV listing, or a malicious package. EPSS [G24] is not used in the decision to open; it is displayed only (`epss_used_for_opening` is `false`). KEV is CISA's Known Exploited Vulnerabilities Catalog [G23].
2. The Hub's maintainer enables the aggregation job. Keep the interval between scheduled runs at 6 hours or less. For the state of the Hub-side implementation, see [Status](#status). A watchdog separate from the aggregation job checks the time of the newest run result and the outcome of recent runs. The watchdog fails when the newest run result is older than the watchdog limit (<!-- policy:watchdog.limit_hours -->8 hours: the 6-hour interval plus 2 hours of `schedule` delay), when the last 2 runs both failed, or when the chain of run results is broken. The limit is the `watchdog.limit_hours` key of the policy file and is 8 hours when the key is omitted. An interval longer than 6 hours exceeds the limit and makes the watchdog fail.
3. Check the cap on new Issues. The cap on new Issues per repository per run is <!-- policy:issue_limits.max_new_issues_per_repo_per_run -->10. When the cap is exceeded, findings that are KEV-listed or malicious packages are opened first and the rest in descending CVSS severity; the aggregation job lists the excess in one summary Issue for that repository.
4. A finding without a severity (no CVSS severity, not KEV-listed, and not a malicious package) is not opened as an Issue for each finding. Once <!-- policy:unscored_review_days -->7 days have passed from the time it can be judged (the later of the advisory's publication time and the time the component version was first observed), it is listed in one summary Issue per repository. The order is by EPSS, descending, and EPSS is used only for the order and the display. A run that could not fetch KEV does not create this summary Issue and does not update or close it. Creating the Issue is the Hub-side implementation; the Hub workflow is not running because its settings are not created, and the creation behaviour has not been checked ([Status](#status)).
5. A malicious package (a `MAL-` identifier) is opened regardless of severity and is not excluded by VEX (`open_if_malicious` is always `true`). The unit for de-duplication is (repository, purl, version). If the same purl and version has both a GHSA (type=malware) and a `MAL-` record, they are merged into one, and `MAL-` is preferred as the representative identifier.
6. A withdrawn `MAL-` is closed with the reason `withdrawn` only when the OSV `GET /v1/vulns/{id}` response succeeds and `withdrawn` can be read as a timestamp. If upstream removed the affected version from the record, it is closed with `feed_version_delisted`. If the response cannot be obtained, or `withdrawn` cannot be read, the Issue is not closed and is recorded in the run result as `malicious_withdrawn_unconfirmed`. If a withdrawn `MAL-` reappears, the closed Issue is reopened.
7. Check what an Issue carries: the vulnerability identifier, the affected component and version, CVSS severity, whether it is KEV-listed, whether it is a malicious package, the EPSS score and fetch date (with the model version), the fixed version, the detection time, and the response-time target deadline. The KEV field `knownRansomwareCampaignUse` is displayed only and is not used in the decision.

Scanners that depend on a CVE database do not detect a malicious package before a CVE is assigned. The AWS Security Blog makes this point [G20] (it is guidance, not a specification). For this reason, malicious packages are looked up separately from the OpenSSF Malicious Packages feed [G21] through OSV [G22].

### Weekly check from the maintainer's machine

The watchdog runs on the Hub's GitHub Actions, the same place as the aggregation job, so it cannot catch two kinds of stoppage. One is that, in a public repository, `schedule` workflows are disabled automatically after 60 days without a commit [G33]. The other is an outage of GitHub Actions itself. The maintainer catches both with a check run weekly from their own machine. The steps below were run on 2026-11-15 in this repository's working tree, with the report written to a throwaway directory. The `supply-chain-runs` branch is not created yet, so step 2 was checked against a throwaway local repository that has a branch of the same name, and steps 3 onward were checked with one record placed in `runs/` of that clone (step 1 was run against the real Hub). The points that were not confirmed are in [Status](#status).

1. Run `gh api 'repos/<Hub owner>/<Hub repository>/actions/workflows?per_page=100' > <file saved from gh api>`.
2. Bring the `supply-chain-runs` branch, which stores the run results, into a clone of the Hub repository (below, `<branch clone>`). Create the clone once, with `git clone --no-checkout --single-branch --branch supply-chain-runs <Hub repository URL> <branch clone>`. Every time, bring it up to date with `git -C <branch clone> fetch origin supply-chain-runs && git -C <branch clone> checkout --detach FETCH_HEAD`. Use `<branch clone>` for this check only, not as a working tree. The `supply-chain-runs` branch does not exist until the Hub's maintainer creates it (checked with `git ls-remote` on 2026-11-15). While it does not exist, this step fails, so steps 3 onward cannot be done.
3. In the root of this repository, run `PYTHONPATH=solutions/supply-chain python -m supply_chain.watchdog_cli --runs-dir <branch clone>/runs --workflows-json <file saved from gh api> --chain-ack docs/agent/supply-chain-chain-ack.json --report-file <report file> --previous-report <report file>`. Pass the same path to `--report-file` and `--previous-report`. `<report file>` is one fixed path that the maintainer chooses; this step and the daily check below use the same file. If the path changes, an overdue check goes undetected or the daily check fails every time.
4. If the exit code is 0 and `healthy` in the report file is `true`, the check is done.
5. If the exit code is 1, read `state` in the report file and follow the row of the table below. The reason for `unhealthy` is printed to standard output.

| `state` in the report file | Cause | Action |
|---|---|---|
| `unhealthy` (the newest run result is too old, or the last 2 runs both failed) | The aggregation job is not running, or is failing | Check the aggregation job's runs on the Hub |
| `unhealthy` (a workflow's `state` is `disabled_inactivity`) | The public repository had no commit for 60 days and the workflow was disabled automatically | Enable the workflow again on the Hub |
| `unhealthy` (a workflow's `state` is `disabled_manually`) | Someone disabled the workflow | Find out why it was disabled, then enable it again |
| `unhealthy` (the chain of run results is broken) | One month has 2 chain tips | Follow [Recovery when the record chain forks](#recovery-when-the-record-chain-forks) |
| `error` | The policy file or the workflow listing could not be used | Read the reason in `policy_error` or on standard output, confirm that the policy file can be read and that the file saved in step 1 is not empty, and start again from step 1. The report file is still written, so the next due date is set |

Notes on step 3. `supply_chain` is not installed, so `PYTHONPATH` is needed; without it the command stops with `No module named 'supply_chain'`. When `--policy-file` is omitted, the command reads `docs/agent/supply-chain-policy.json` in the root of this repository, as `git` reports it, whatever the working directory is. A relative `--policy-file` that does not exist from the working directory is looked up from the repository root. `--chain-ack` is the ledger that records accepted forks; when it is omitted, no fork is treated as accepted.

The report file keeps the run time, `healthy`, `state` (`ok`, `unhealthy`, or `error`), and the next due date `next_check_due` (8 days after the run). A run that starts after the previous due date exits 1 and leaves `previous_check_overdue: true` in the report. To catch the check itself stopping, run `PYTHONPATH=solutions/supply-chain python -m supply_chain.watchdog_cli --overdue-check <report file>` in the root of this repository, as a separate launchd job from the weekly check (every day at 09:00 JST). It exits 1 when the due date has passed or when there is no report. The launchd job shows the notification when it receives this exit code (the command itself only sets the exit code and prints a message to standard output). For the case where the whole machine stops, put a recurring entry for this weekly check in the maintainer's calendar. If the entry fires and the check was not done, the stopped machine is noticed.

Start the check from launchd on the maintainer's machine, and have the job show a notification when the check fails (exit code 1), for example with `display notification` in `osascript`. In the plist, write the absolute paths of `gh`, `git`, and `python` in `ProgramArguments` and in the `PATH` of `EnvironmentVariables`, and set the log location with `StandardOutPath` and `StandardErrorPath`. cron does not run jobs while the machine sleeps or is off, and waits for the next scheduled time, so use launchd on a machine that sleeps. A launchd `StartCalendarInterval` job whose time passes during sleep runs on wake. Apple's document is an archive, and the behaviour of the current macOS has not been checked. On 2026-11-15, a throwaway plist was loaded with `launchctl bootstrap` and started with `kickstart`; `--overdue-check` returned exit code 1 inside the job, and `osascript display notification` was called with exit code 0 (verified). That the banner appeared on screen, and a run after waking from sleep, have not been confirmed (open). Once the Hub-side implementation is running, this check is the only way to notice that the Hub's watchdog has stopped. No sample setup is stored in the repository.

### Recovery when the record chain forks

Use these steps when the watchdog reports a break in the chain of run records and one month has 2 tips (records with no child), or when the aggregation job fails with `the month has 2 chain tips`. A month gets 2 tips when two writes name the same previous record and race, or when a record is placed by hand (as the implementation describes it; an actual fork has not been observed). Do not delete or edit any record. Deleting or editing makes the chain lose its purpose of detecting tampering. Leave the abandoned record in place and put it outside the chain.

1. Detect. In the root of this repository, run `PYTHONPATH=solutions/supply-chain python -m supply_chain.chain_recovery --runs-dir <branch clone>/runs --ledger docs/agent/supply-chain-chain-ack.json detect`. It prints the SHA-256 and the path of each tip, and exits 1 when a fork is not in the ledger.
2. Open the records at the 2 paths that step 1 printed, and compare their `prev_record_sha256` (both name the same previous record), their start time (`started_at`) and their bodies. The criterion for which one to put outside the chain is set by whoever writes the records on the Hub side (`open`). Until it is set, the maintainer looks at the Hub's run history, keeps the record that was written first, and writes the reason in the Issue or PR that step 3 names in `--decision`.
3. Register. Run the same command ending in `isolate --abandon <SHA-256 of the tip to abandon> --decision <Issue or PR number, or its URL>`. Write `Issue 123`, `PR 45`, or the URL of a GitHub Issue or pull request in `--decision`; free text is refused. It adds one entry to the ledger. It also refuses a record that has a child, an unknown SHA-256, a record of a month with no fork, a duplicate entry, and a registration that abandons every tip of a month. Open a PR with the ledger change, and merge it after the maintainer has checked it by eye.
4. Confirm the reconnection. Run the command ending in `reconnect --month <YYYY-MM>`. If it prints one SHA-256, the month has one tip, and the next record puts that value in `prev_record_sha256`.

A registered record is read as outside the chain by the writer, the month-end seal, and the watchdog. The three operations were run on 2026-11-15 in a throwaway directory with 2 tips created in one month: detection exited 1, reconnection after registration printed one SHA-256, and the watchdog given the ledger exited 0. That a free-text `--decision` and a registration that abandons every tip of a month are refused was also confirmed on the same day. The part in which the aggregation job reads the ledger and resumes writing is on the Hub side and is in Hub PR #383 (not merged); it has not been run to confirm. A rewrite of the body of a tip record is taken into the chain by the next write and is not detected until the month-end seal.

### policy file keys

- `opening_threshold.min_cvss_severity`, `open_if_kev_listed`, `open_if_malicious`, `epss_used_for_opening`
- `issue_limits.max_new_issues_per_repo_per_run`, `unscored_review_days`
- `vex.exclude_statuses`, `vex.malicious_never_suppressed`, `vex.max_age_days` (the section [Operating VEX](#operating-vex))
- `response_target.*` (the section [Response targets](#response-targets))

### Choosing a tool

Choose how to find vulnerabilities by what you want to see. The table below lists three options with the same two columns, use and trade-offs. No ranking is given.

| Option | Suited to | Trade-offs |
|---|---|---|
| Aggregation job (adopted) | Applying the same threshold across 12 repositories and tracking each in Issues per repository | Depends on a scheduled Hub job and external feeds (KEV, EPSS, OSV). Issues are per repository, so Inspector findings, which are per account and resource, are not included as sources of Issues. Deployed-state vulnerabilities that do not correspond to a repository, such as libraries bundled with a runtime, do not become Issues |
| GitHub Dependabot alerts only | Not adding any mechanism and viewing alerts on the repository's screen | Thresholds and deadlines rely on per-repository settings. In a repository where Dependabot alerts are disabled, neither alerts nor the Renovate fix PRs that read them are expected to be created (hypothesis) [E-055]. Handling of malicious packages has to be arranged separately |
| Amazon Inspector findings (aggregated in AWS Security Hub CSPM) [G10] | Viewing deployed Lambda functions, ECR images, and EC2 instances per account and Region | Requires enabling Inspector and Security Hub and their charges. No Issue is created in the repository. Code Security findings are not sent to Security Hub CSPM [E-046]. AWS Security Hub (OCSF) does not receive third-party findings, and custom findings appear only in CSPM [E-050]. The AWS SDK bundled with the Lambda runtime [E-047], functions encrypted with a customer managed key [E-048], and functions not invoked or updated in the last 90 days [E-049] are out of the scan |

When the same vulnerability appears both as an SBOM-derived finding and as an Inspector finding, an Issue is created only from the SBOM-derived finding. Inspector findings are handled on the Security Hub CSPM side, and the fix is made through the repository's Issue. What Inspector does not scan is not visible to the aggregation job either. Do not read "does not become an Issue" as "Inspector can catch it".

## Defending at intake

The matching Well-Architected best practices are SEC11-BP05, SEC11-BP06, and SEC11-BP07. See the [framework mapping](cyber-resilience-framework-mapping.md#best-practice-ids) for the mapping table.

The purpose is to keep freshly published versions, references without a pinned version, and artifacts whose provenance cannot be verified out of the repository.

### Steps

1. Add the Renovate shared preset to `extends` in the repository's `renovate.json`. Pin the reference to a 40-character SHA or a tag; do not reference a branch name and do not omit the reference. Reference only the Hub's shared presets (`renovate/supply-chain`, and `renovate/supply-chain-automerge` for automerge). Do not put any other `github>` or `local>` preset in `extends`. Put the Hub's preset last in `extends`. Of Renovate's built-in presets, only those on the gate's allowlist are accepted.
   - On the allowlist: `config:recommended`, `config:best-practices`, `helpers:pinGitHubActionDigests`, `helpers:pinGitHubActionDigestsToSemver`.
   - On the allowlist: seven presets that start with `:` and only change the dashboard, commit messages, or maintenance (for example `:dependencyDashboard`, `:semanticCommits`), and the labelling presets with an argument (`:label(…)`, `:assignee(…)`, `:reviewer(…)`, `:timezone(…)`).
   - On the allowlist: the `group:`, `mergeConfidence:`, `replacements:`, `workarounds:` and `monorepo:` families, except names that contain disable, skip, automerge, ignore, immediate, notpending, never, minimumreleaseage or enabled.
   - Not on the allowlist: any other built-in preset, such as `:disableRenovate` or `security:minimumReleaseAgeNpm`. It can change what the Hub preset sets, and the gate fails on it.
   - The gate checks every nested `extends`, whether an array or a string and including those inside `packageRules`, against the same allowlist (whether Renovate resolves a nested `extends` has not been confirmed; open, so the gate treats it as resolved). Review the allowlist after running it against each Spoke's `renovate.json`.
   - The gate checks the first config file found in the order in which Renovate looks for one: `renovate.json`, `renovate.jsonc`, `renovate.json5`, the same three under `.github/` and under `.gitlab/`, `.renovaterc`, `.renovaterc.json`, `.renovaterc.jsonc`, `.renovaterc.json5`, and the `renovate` section of `package.json` (14 places). It fails when two or more exist, because Renovate reads only the first one and it would be unclear which one was checked. It also fails when the chosen file is JSONC, JSON5 or has no extension and cannot be read as JSON. A self-hosted `configFileNames` setting is not visible from the repository and is outside the check.
   - The Hub is designed to publish the `supply-chain-preset-v*` tags as immutable releases with the preset JSON attached (after publication a tag cannot be moved to another commit [G31]). Until the Hub's preset has a tag, do not add `extends`. Do not write a provisional tag or a guessed SHA. A tag reference is allowed as a temporary measure until the pilot has shown once that the form `github>…#<SHA>` resolves in Renovate.
2. Do not override `minimumReleaseAge`, `minimumReleaseAgeBehaviour`, `minimumReleaseAgePackageManager`, `automerge`, `platformAutomerge`, `internalChecksFilter`, `internalChecksAsSuccess`, `ignoreTests`, `prCreation`, `registryUrls`, `hostRules`, or `ignorePresets` in the repository's own settings. The same goes for `minimumReleaseAge`, `prCreation`, and `ignoreTests` under `vulnerabilityAlerts`, and for `enabled: false` and `osvVulnerabilityAlerts: false`. The gate fails on a violation at any depth of the settings tree. It checks the top level, each `packageRules` entry, the object of each manager (such as `npm`), the object of each update type (such as `major`), and anything nested in them. It also checks inside `lockFileMaintenance` and `vulnerabilityAlerts`, and anything nested in them. Every key whose name starts with `minimumReleaseAge` is also forbidden, including `minimumReleaseAgeBuffer` and `minimumReleaseAgePackageManagerSync`. It does not check below `hostRules`, `customManagers`, `regexManagers`, or `customDatasources`, which hold definitions and not option values (whether `customManagers` takes option values is not confirmed; hypothesis). `enabled: false` directly under `lockFileMaintenance` is the same as the default and does not stop updates, so it is not a violation. The directly nested keys of `vulnerabilityAlerts` are read by its own check. Keep the existing `vulnerabilityAlerts` (enabled, `security` label) and `osvVulnerabilityAlerts` (enabled) at the same values.
3. Check the Cooldown values. Major updates wait <!-- policy:cooldown_days.major -->7 days, and every other update except a pin (minor, patch, and digest included) waits <!-- policy:cooldown_days.default -->3 days. Both are conventional values, not measured ones. A pin (`pinDigest`) update does not wait. It only freezes what the reference already resolves to, and waiting would prolong the unpinned state for a frequently released package [G1].
4. Vulnerability-fix PRs are not subject to the Cooldown, so do not automerge them and require a human approving review. According to Renovate's documentation, vulnerability-fix PRs are created without the Cooldown [G1].
5. Enable GitHub Dependabot alerts. Renovate's vulnerability-fix path reads Dependabot alerts, so fix PRs are not expected to be created in a repository where they are disabled (hypothesis) [E-055].
6. For updates to which Renovate does not apply the Cooldown (`lockFileMaintenance`) and for transitive dependencies, set a waiting period on the package-manager side. The value is the same <!-- policy:package_manager_wait.default_days -->3 days as the Cooldown for ordinary updates. It is not written in the policy file; it is derived from `cooldown_days` (the marker just before the number is what the verification gate compares with the `cooldown_days` value. The policy file schema still accepts `package_manager_wait` as an optional entry, but the derived form is unfinished, so do not write it; if written, both `default_days` and `major_days` are required). A package manager applies its waiting period uniformly to every package in the lock file, so major updates cannot have a different value. The setting names and units for each tool are in the table below.

   | Tool | Setting | Unit | Status |
   |---|---|---|---|
   | npm | `min-release-age` | Days (integer) | Checked in [G3]. The gate compares the value |
   | pnpm | `minimumReleaseAge` (`pnpm-workspace.yaml`) | Minutes (4320 for 3 days) | The gate compares it as minutes. The pnpm documentation has not been read (open) |
   | uv | `exclude-newer` (`pyproject.toml`) | The form `N days` | The gate compares it as days. The uv documentation has not been read (open) |
   | pip | `--uploaded-prior-to` | An absolute time | The gate does not compare it. The pip documentation has not been read (open) |

7. Pin production dependencies to exact versions: `==` for Python, and an exact version without an operator for npm. Pin third-party GitHub Actions to a 40-character commit SHA, and tools to an exact version plus an image `sha256:` digest. The Hub's `cooldown-pinning-check` verifies pinning and that the Cooldown values match the policy file.
8. Call the Hub's `vex-validate` and `cooldown-pinning-check` from a caller workflow, pinned to a 40-character SHA (see the example in the section [Loosely coupled updates](#loosely-coupled-updates)).
9. A repository that publishes release artifacts follows the steps in the section [Verifying provenance](#verifying-provenance).

### Security fixes and the package-manager wait

In a repository that has a package-manager waiting period, a vulnerability-fix PR skips Renovate's Cooldown but not the package manager's waiting period. Until the waiting period has passed since the fixed version was published, the lock file update fails and the PR shows an artifact error [G1]. During that time, do the following.

1. A maintainer opens a PR that excludes only the one package being fixed (npm `min-release-age-exclude`, or the equivalent exclusion in another tool).
2. The maintainer checks the publication time and the advisory, and then adds the exclusion.
3. After the fix is merged, remove the exclusion.

The verification gate warns (without failing) when `.npmrc` still has one or more `min-release-age-exclude` entries. `npm audit fix` can also fail to install a patched version because of the waiting period [E-056].

### Checklist for vulnerability-fix pull requests

A malicious release disguised as a vulnerability fix can become a PR without going through the Cooldown. Before merging a fix PR, the approver checks the following.

- The publication time in the PR body (Age), the diff, and any change of publisher
- That the version being updated to is not listed in OpenSSF Malicious Packages [G21]

Renovate's detection of malicious packages is experimental in its documentation and works only inside `osvVulnerabilityAlerts` [G2]. Do not write that Renovate does not create PRs for malicious versions, and do not rely on it as the protection against malicious packages. If a `MAL-` record is published after a merge, the aggregation job opens an Issue.

### Images from registries without release timestamps

Digest and pin updates for images in registries that do not return release times (GHCR, Quay, ECR) are held indefinitely under the default `minimumReleaseAgeBehaviour` (`timestamp-required`) [E-045]. This project keeps `timestamp-required`, and for those images it stops at creating the PR without automerging. A maintainer checks the publication time in the PR. To lift the hold, set `timestamp-optional` in an individual rule. Once lifted, the Cooldown does not apply to that image.

### Limit of the Cooldown for GitHub Actions

For an update to an Action pinned by SHA, Renovate takes the publication time from `github-tags` as the commit's `committedDate` (not the push time). Even if an existing tag is force-pushed, a digest update is judged by the original release date [G1]. For that reason, the <!-- policy:cooldown_days.default -->3-day Cooldown does not count as protection against a compromise that moves a tag (hypothesis; whether a test tag that points to a commit with a past date passes the age check has not been confirmed by running it). Updates to third-party Actions are not automerged (`third_party_action` in the policy file `automerge.exclude`).

Even in a repository that adopts a lockfile for the dependencies of Actions workflows (`.github/workflows/actions.lock`), do not replace the SHA pin in `uses:` with the existence of the lockfile. Whether a lockfile may replace the SHA pin is `open`, because the maturity of the feature has not been confirmed; decide after the pilot. Until then, require the SHA pin.

### Basis and limits of the Cooldown values

The adopted values are 3 days for ordinary updates and 7 days for major updates. The alternative compared is 7 days and 14 days. The "window" here is the time between a malicious version being published and its being withdrawn.

- 3 and 7 days: ordinary updates are delayed little. A compromise whose window is shorter than 3 days is stopped, but one whose window is the same or longer is not.
- 7 and 14 days: for ordinary updates this can also stop compromises whose window is longer than 3 days and up to 7 days. Ordinary updates are delayed by a week, and feature updates arrive later. Vulnerability fixes skip the Cooldown, so fixes are not delayed further.

Neither pair rests on a measurement of the window between publication and withdrawal. A public article that tallies window lengths exists (secondary information, with a small sample), but its primary sources have not been read, so this guide does not use it as a basis. The pilot measures the number of violations and the delay of updates, and then the values are reviewed.

### Choosing a pinned SHA

Pin third-party Actions to a 40-character commit SHA and keep a version comment (in the form `# v4.2.2`). With the comment, Renovate can update the tag and the SHA together. Choose a SHA that belongs to the Action's own repository and not to a fork [G32].

`make check-pinned-sha-exist` (it needs the network, so it is not part of `make test`) asks GitHub whether the SHA exists in the referenced repository and also whether that commit is an ancestor of the default branch or equals the commit that the version comment's tag points to. A commit that exists only in a fork is not caught when the commit-lookup API succeeds. GitHub documents a workflow dependency lockfile, but its maturity could not be confirmed, so whether it can replace SHA pinning is `open` and is decided after the pilot. Until then, SHA pinning is required.

### policy file keys and a pinned-reference example

The matching keys are `cooldown_days.default`, `cooldown_days.major`, `dependency_scope.non_production_paths`, and `renovate_preset` (optional; record the tag and the 40-character `commit` after the Hub publishes the tag). The package-manager waiting period is derived from `cooldown_days`. A `renovate.json` example follows. Replace `<tag>` with the value at the time the Hub tags the preset.

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

That this reference form resolves in Renovate has not been confirmed by running it ([Status](#status)). If the preset cannot be resolved, return the reference to the previous SHA or tag. When `renovate_preset` is recorded in the policy file, the part of a Spoke's reference after `#` must equal its `tag` or `commit`. `make check-pinned-sha-exist` checks that the Hub's tag points to that `commit`, and fails with `tag-moved` if it does not.

### Choosing a tool

There are three options for where to place the Cooldown. No ranking is given, and they can be combined.

| Option | Suited to | Trade-offs |
|---|---|---|
| Renovate `minimumReleaseAge` (adopted) | Making the update PR wait at the point it is created; keeping the value in one place, the Hub preset | Does not reach pin, `lockFileMaintenance`, or transitive dependencies. Digest updates for images in GHCR, Quay, and ECR are held indefinitely [E-045] |
| Waiting period on the package-manager side | Covering transitive dependencies and installs that do not go through Renovate. Use the same number of days as `cooldown_days` in the policy file | Units and setting names differ by tool, and the gate has more files to read. With npm, the waiting period can keep `npm audit fix` from installing a patched version [E-056] |
| No waiting period | Taking in fixes as fast as possible; few enough updates that a person can review all of them | A malicious release can be taken in before it is withdrawn. A person has to check each fresh version every time |

Pinning methods also involve a choice. Pinning to a commit SHA or digest prevents the target from being swapped, but it assumes updates are received through Renovate PRs. Pinning to a tag is easier to read, but a tag can be moved. A lock file with hash-checked installs (`npm ci`, `--require-hashes`) pins transitive dependencies too, but whether to make it mandatory is decided after the pilot measures the number of violations.

## Loosely coupled updates

The matching Well-Architected best practice is SEC11-BP06. See the [framework mapping](cyber-resilience-framework-mapping.md#best-practice-ids) for the mapping table.

The purpose is to apply updates to dependencies and workflows in small steps that can be rolled back, so that when an update breaks, the impact stays within the repositories that took it in.

### Steps

1. In one repository, let only Renovate create update PRs. Do not run Dependabot version-update PRs alongside it. Keep Dependabot alerts enabled, as in step 5 of [Defending at intake](#defending-at-intake).
2. Pin calls to the Hub's reusable workflows to a 40-character SHA and add a version comment (`# <tag>`). With the version comment, Renovate can update the SHA and the tag together.
3. When a Hub workflow breaks, open a PR that returns the reference SHA to the previous one and merge it once CI passes. This can be done without waiting for a Hub fix. Only the repositories that updated their reference to the broken version stop; repositories that kept the previous SHA are not affected. Confirm the rollback by the caller job finishing successfully.
4. Do not automerge updates that reference Hub workflows (`hub_reusable_workflow` in the policy file `automerge.exclude`). If they were automerged, a change to a verification gate would reach every Spoke automatically after the Cooldown.
5. Update Lambda functions with a gradual deployment and automatic rollback on an alarm. The reference is `EventTransformerLambda` in this repository's [`templates/event-driven.yaml`](../../templates/event-driven.yaml). It has `AutoPublishAlias: live`, a `DeploymentPreference` of `Canary10Percent10Minutes`, and `UpdateRuntimeOn: FunctionUpdate` in `RuntimeManagementConfig`. A rollback is triggered by four alarms (errors on the new version, records the new version returned to the queue, the new version's run time exceeding half of the timeout, and throttling of the function) and by a failure of the `PreTraffic` hook, which sends a test message to the real handler before traffic moves. An alarm on errors of the whole alias (old and new version together) exists but is notification only, because an error of the old version would roll back a healthy new version. When a CodeDeploy deployment fails or stops, an EventBridge rule sends it to the existing security notification topic. The alarm thresholds are not measured (hypothesis). The composition was confirmed by reading the template and by passing cfn-lint, cfn-guard, and Checkov; the template was not deployed, and traffic shifting and rollback were not observed. Confirmation in a real deployment belongs to the second pillar.
6. For upgrading self-managed ONTAP, follow the [ONTAP upgrade procedure](../ontap-native/ontap-upgrade-for-security-advisories.md).

### policy file keys and a pinned-reference example

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
| Dependabot version updates | Staying with built-in GitHub features and not adding an execution platform | This project's gates and policy file assume Renovate settings, so the same checks have to be provided separately if you use it. This project does not provide a way to distribute shared settings from the Hub |
| Update by hand | A person wants to see every update; few repositories and dependencies | Effort grows with the number of updates, and omissions are easier to make |

## Automerge scope

Only an update that meets all four conditions is automerged: (a) a dependency declared for development, or an update to an Action owned by GitHub (under `actions/`); (b) a patch update; (c) the Cooldown has elapsed; and (d) every CI check required by branch protection has passed. The assumption is that, in one repository, only Renovate creates update PRs; do not run it alongside Dependabot version-update PRs.

### In scope and out of scope

| Kind of update | Automerge | Reason |
|---|---|---|
| Patch updates to npm `devDependencies` | In scope | A dependency declared for development, and a patch update |
| Patch updates to GitHub's own Actions under `actions/` | In scope | An Action owned by GitHub, and a patch update |
| Updates to third-party GitHub Actions | Out of scope | The age check is likely not to catch a moved tag ([Limit of the Cooldown for GitHub Actions](#limit-of-the-cooldown-for-github-actions)). The PR is created and a person reviews it |
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
| GitHub's own Actions under `actions/` | Applies to patch updates | Third-party Actions and Hub reusable workflows are excluded |
| Mostly Python (`requirements.txt`, `pyproject.toml`) | Does not apply | Development or runtime role cannot be determined, so these are out of scope. Do not expect automerge in a Python-centered repository |
| AWS CDK (npm `dependencies`) | Does not apply | Treated as runtime dependencies |
| Container image digests | Does not apply | Digest-only updates are out of scope |

### Conditions and steps for enabling it

Automerge starts disabled in every repository. The policy file `automerge.enabled_repositories` starts as an empty array, and repositories are added one by one after they have been confirmed.

1. A maintainer checks that the repository's default-branch ruleset has at least one required CI check. Without any required check, GitHub's automerge can merge without waiting for tests to finish. This is a design understanding based on Renovate's documentation and has not been confirmed by running it.
2. A maintainer writes the number of required checks per repository into `docs/agent/automerge-required-checks.json` by hand (`{"required_checks": {"<owner>/<name>": count}}`). It is not replaced automatically from the aggregation job's output. The maintainer creates this file when the first repository is ready to be enabled. The gate fails unless each repository in `enabled_repositories` has a count of 1 or more.
3. Add the repository to the policy file `automerge.enabled_repositories`.
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

VEX records, with a basis, a judgment such as "this vulnerability does not affect" a given version of a component. The format is [OpenVEX](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md) v0.2.0 [G4], and the files live in the repository's `.vex/` directory.

### Rules

- One VEX document holds exactly one statement. The author of a judgment is recorded as a role name (the VEX approver), not as a personal name or email address.
- A judgment drafted by an AI agent is an auxiliary signal, not a final judgment. Record, for each judgment, that an AI agent drafted it.
- A judgment that has not been approved is not used as a reason to hold back an Issue. Approval means that a VEX approver reviews the PR as a Code Owner and that the PR is merged to the default branch.
- If the component version a judgment covers differs from the finding's version, the judgment is not used. When the component version changes, the judgment no longer applies.
- A judgment can hold back an Issue only when the finding's main identifier is written in the statement's own `vulnerability.name` or `aliases`. The aliases that the finding carries are not used for matching. A statement named after a GHSA that several CVEs share holds back no CVE's finding unless its own `aliases` lists that CVE. This does not change when the finding of another CVE with the same GHSA disappears. A statement that matches only an alias of the finding is not used to hold back the Issue. For a finding that meets the threshold for opening an Issue, it is recorded in the run result's `rejected_vex` with the reason `vex_names_finding_alias_only`, listed in the plan's `vex_name_only_ghsa` (repository, the finding's main identifier, statement path), and its path is written as `vex_names_alias_only` in the state block of that finding's Issue. Write in `vulnerability.name` the identifier that appears in the Issue title (the CVE, if there is one). To decide on a GHSA, write the CVE in `aliases`. Only for a finding of a malicious package are aliases also matched; a statement that matches is recorded as `malicious_package_not_suppressible` (it still holds nothing back). One statement does not name two or more different CVEs in `name` and `aliases` together (identifiers are trimmed and upper-cased before they are counted).
- The time of a judgment is the statement's `timestamp`, or else the document's `timestamp`. When there are several judgments for the same vulnerability and component version, only the newest by time is used. When a statement with an excluding status loses to a newer statement with a non-excluding status, `vex_superseded` is recorded only if none of the identifiers that the statement names uses it to exclude. A statement that lost for some identifiers only is still used for the others, so it is not recorded. OpenVEX v0.2.0 has no field that marks one statement as replacing another; newer and older are decided by time. When you confirm a judgment again, issue it again with a new `timestamp`.
- A judgment older than <!-- policy:vex.max_age_days -->180 days, and a judgment whose time is more than 5 minutes ahead of the run time, are not used. A judgment is also not used when the vulnerability was added to KEV after the judgment; a new review is required. The latest KEV listing date among the finding's identifiers (the main identifier and the aliases) is used, and a listing on the same day as the judgment counts as after it. A judgment that was not used is recorded in the run result's `rejected_vex` with its reason (`vex_expired`, `vex_superseded`, `vex_timestamp_in_future`, `vex_predates_kev`, `vex_names_finding_alias_only`).
- A `not_affected` or `fixed` judgment carries a non-empty `impact_statement`: for `not_affected`, the facts checked and where; for `fixed`, the fixed version and how it was checked. A `justification` label alone is not enough as a basis. A judgment without one is not used, and `vex_missing_impact_statement` is recorded.
- For the `.vex/` judgments, the verification gate fails on a missing `impact_statement`, a future time, `products` that are not purls, or a statement that names two or more different CVEs (kind `multi-cve`). An expired or superseded judgment only produces a warning. A review after a KEV listing needs the KEV catalog, so the gate does not decide it; the aggregation job records it.
- `products` holds the purl of the component. OpenVEX `subcomponents` is not used; this is this project's own practice, and compatibility with other VEX-aware tools is not guaranteed.
- Only the aggregation job reads `.vex/`. VEX is not passed to the layer B scanner.
- A judgment whose vulnerability identifier is `MAL-` is not used to hold back an Issue, whether its status is `not_affected` or `fixed`. A malicious package cannot be excluded with VEX.
- Write the reason for a decision in the body of the review in which the VEX approver sets `APPROVED`, under a heading "判断理由" (the `vex-validate` gate looks for this Japanese heading), with a body of 20 characters or more, not in the PR body. The author of a PR can edit the PR body. The PR template holds only fields that a machine fills in: the command used to check reachability and the SHA-256 of its output, the purl of the target version, and the advisory URL with the SHA-256 at retrieval.
- `not_affected` is a record that "there is no impact". It is not an acceptance of the risk of leaving something unfixed. If you accept a risk and do not fix it, keep that record somewhere other than VEX, such as an Issue comment.
- A judgment that rests on whether code runs, such as `vulnerable_code_not_in_execute_path`, carries evidence (the analysis method and the call path). A judgment without evidence is not approved.

### Constraint for single-owner repositories

VEX approval is enforced with the repository's ruleset. It has three settings. Set the GitHub setting "required approving reviews" to 0. Turn on "require review from Code Owners". Make CODEOWNERS cover `/.vex/` only. A review by a VEX approver (a human) other than the PR author is the condition for merging a PR that changes `.vex/`. An AI agent's review is not counted toward this condition. A PR that does not touch `.vex/` can be merged without approval.

In a personal-account repository with a single owner, these constraints apply.

- Only an arrangement in which an AI agent with an identity separate from the owner's (a GitHub App or a dedicated account) creates the VEX PR and the owner approves it meets the merge condition for `.vex/` PRs. Give that identity only the permission to create PRs that contain `.vex/`; do not give it write access to Issues or write access to Contents on the default branch.
- An arrangement in which the owner creates the VEX PR does not meet the merge condition for `.vex/` PRs. The owner cannot approve their own PR, so the merge condition cannot be met.
- Do not start the arrangement in which an AI agent creates VEX PRs until the separate identity exists. Providing the identity is a maintainer's task; an AI agent does not stand in for it.

Verify the setting in two ways: confirm that a `.vex/` PR created by the owner cannot be merged, and that a PR that does not touch `.vex/` can be merged.

### Monthly review

A wrong `not_affected` keeps the Issue for that (repository, vulnerability, version) combination held back. The impact is limited to that combination, and when the component version changes the judgment stops applying. Once a month, compare the basis of each approved VEX document with the component version. If you find an error, a VEX approver approves and merges a PR that deletes that VEX document (or changes it to `affected`). Confirm by checking that the Issue for that finding is reopened or opened in the next aggregation job run. Also check through the GitHub REST API that `bypass_actors` of the ruleset is empty.

## Verifying provenance

A provenance attestation lets whoever takes in a release artifact verify which commit and which workflow produced it. The target level is SLSA Build L2 [G7], where each repository uses `actions/attest` in its own workflow [G5].

### Producer-side steps

1. Add `actions/attest` (pinned by SHA) to the release workflow and create one attestation per artifact. The job permissions are `id-token: write`, `attestations: write`, and `contents: read`.
2. Place the publish step after the provenance step and connect them with `needs`. If creating the attestation fails, do not publish the release.
3. Attach the attestation bundle to the release as `*.sigstore.json`. Attach it to the release SBOM as well.
4. Building and attesting inside a Hub reusable workflow corresponds to L3. This project does not adopt L3, because a Hub failure would then also affect releases and the set of repositories that could adopt it would be narrower still. L3 is the option that gives isolation between runs.

As checked on 2026-11-10, none of the target repositories attached release artifacts, published packages to a public registry, or pushed images. Whether GitHub Packages holds any package was not checked, because the account used for the check lacked the `read:packages` permission. [FSx-for-ONTAP-Observability-integrations](https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations) has 6 releases with 0 attached files, and it becomes the first adopter once it starts attaching files. When a repository starts publishing packages to a public registry, re-read that registry's documentation and decide the publication criteria then.

### Verification steps for artifact consumers

The command is `gh attestation verify` [G6].

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

1. Check whether the release is an immutable release [G31]. If it is not, treat its assets as something that can be replaced later.
2. If `checksums.txt` exists, compare it with the hash of the file you fetched.
3. If a sigstore bundle exists, verify the signature.
4. If a SLSA provenance exists, verify the expected repository and workflow.
5. If none exists, rely only on the digest pin and record that distribution verification was skipped.

The trade-off is that the tools used for verification (cosign, slsa-verifier, and so on) are themselves something more to pin and update.

## Response targets

A response-time target is a "target". Until it has been measured in operation, it is not called an SLO. The values live in the policy file `response_target`, and the numbers in this guide match the policy file.

| Item | Value | Span it measures |
|---|---|---|
| Detection | <!-- policy:response_target.detect_hours -->24 hours | From the detection starting point to Issue creation |
| Fix (KEV-listed, or a malicious package) | <!-- policy:response_target.fix_days_kev_or_malicious -->7 days | From Issue creation to closing |
| Fix (CVSS severity High or above, not KEV-listed, and not a malicious package) | <!-- policy:response_target.fix_days_high -->14 days (reference value) | From Issue creation to closing |

The <!-- policy:response_target.fix_days_high -->14 days for High and above (not KEV-listed) is a reference value; the pilot decides, from its results, whether to keep 14 days or extend to 30 days. A finding that is both KEV-listed and High or above gets 7 days. If the vulnerability behind an open High-or-above Issue is later added to KEV, the aggregation job updates the deadline to the earlier of the existing deadline and 7 days after the run that detected the listing.

Except when KEV alone satisfies the trigger (next paragraph), the detection starting point is the later of two times. The first is when the finding first met the opening condition (the advisory's publication time for CVSS, and the feed entry's publication time for a malicious package). The second is the time of the run in which the aggregation job first observed that component version. An Issue whose starting point cannot be obtained is recorded with the starting point as "unknown", left out of the detection results, and the number left out is written to the run result.

When KEV alone satisfies the trigger, record the start as two times, a lower bound and an upper bound. The KEV date added carries a date only, no time of day, so the lower bound is 00:00:00 UTC on that date. The upper bound is the publication time (`dateReleased`) of the first KEV catalogue in which the aggregation job read the entry. An entry is published by `dateReleased` at the latest, so the true start lies between the two bounds. Measure the detection result from each bound to Issue creation. A miss of the 24-hour target is certain only when the time measured from the upper bound also exceeds 24 hours. When only the time measured from the lower bound exceeds it, count it as "possibly missed", not as a certain overrun.

The 24-hour detection target is this project's internal target. It is not the deadline for the early warning to the authorities (within 24 hours of becoming aware) that the EU Cyber Resilience Act requires of manufacturers for actively exploited vulnerabilities [G25]. The reporting obligation under that act started on 2026-09-11 (the European Commission's [Cyber Resilience Act - Reporting obligations](https://digital-strategy.ec.europa.eu/en/policies/cra-reporting), checked 2026-11-14). The creation time of an Issue in this project can serve as a record of "the time of becoming aware" for a product's manufacturer. Whether the artifacts of your repositories are products placed on the EU market, and whether you are a manufacturer, is for the service owner to decide with their own legal review. This guide does not make that judgment.

### Replacing the values with your own

This procedure is for the maintainer of this repository when changing a value. If you adopt the controls in your own repositories, copy the policy file and then follow the same procedure to change values.

1. Open a PR that rewrites the three values in the policy file `response_target` (`detect_hours`, `fix_days_kev_or_malicious`, `fix_days_high`) to your own targets. The values are positive integers; the parser rejects negative or non-integer values.
2. In the same PR, rewrite the number right after each marker that starts with `policy:` (an HTML comment) in the Japanese and English versions of this guide to the same value. The overall plan for the three pillars has the same markers.
3. The `guide-values` gate (`scripts/supply_chain_checks/guide_values.py`) checks that the number right after each `policy:` marker in this guide and in the overall plan for the three pillars matches the policy file. On a mismatch it fails and prints the marker, the expected value, and the file and line. `make check-supply-chain` runs it, and it is a prerequisite of `make test`.
4. After the change, see in the next monthly review (the section [Using actual results in the PDCA cycle](#using-actual-results-in-the-pdca-cycle)) how the results come out against the new targets.

### Conditions for calling a response-time target an SLO

A response-time target is not called an SLO until the following conditions are met.

1. The SLI is the share of Issues whose deadline for opening or fixing fell within the evaluation period and that were opened or fixed by the deadline. Detection and fixing are separate SLIs. The denominator is the Issues that were open when their deadline fell and whose closing reason is `resolved` or that are still open; `vex_not_affected` and `withdrawn` are left out. The detection SLI counts only the findings that were opened as Issues and does not count findings that were never opened; a missed opening is looked for separately in the monthly review.
2. The evaluation period is a moving window of 28 calendar days.
3. The minimum condition for promotion is at least 20 Issues whose deadline fell within the evaluation period, for each of detection and fixing. 20 is a rough guide (hypothesis). While there are fewer, record the count and the individual reasons rather than a share.
4. Before promotion, in addition to recording overdue Issues in the run result, put the `response-target-overdue` label on the Issue and make it subject to the maintainer's review. The implementation that applies the label is on the Hub side, and whether the published version applies it has not been checked.
5. The target shares to set after promotion (for example 95% for detection and 90% for fixing) are decided from the pilot's results. Do not fix values before measuring.
6. When the share stays below the target for 2 evaluation periods in a row after promotion, go back to the minimum condition of 20 Issues, stop calling the target an SLO, and return to the practice used before promotion.

### Comparison with other deadlines

As material for replacing the reference values of the response-time target, the deadlines of public documents are summarized. These deadlines are imposed by each document on the organizations or scheme participants it covers, and apply neither to this project nor to a service owner. They are not a judgment about which value is correct. The source of each row is given by the number in the Source column, which refers to the [References](#references).

| How it divides cases | Example deadlines | Starting point | Who it applies to | Source |
|---|---|---|---|---|
| Public examples (2) that divide by CVSS base score or vendor severity | 14 days for High and above (CVSS 7 or higher) | Release of the update | Organizations that take part in a certification or evaluation scheme | [G27], [G28] |
| A public directive that divides by four variables: whether exposed, KEV listing, whether an attacker can automate, and technical impact (CVSS is not used) | 3 days, 14 days, 60 days, or the next system update | The earlier of the KEV addition and identification on the asset | The agencies the directive covers | [G29] |

In this project, the starting point of a fix is Issue creation. Before it comes the 24-hour detection target, measured from the detection starting point to Issue creation. The deadlines in the table therefore cannot be compared from the same starting point. The 7 days for KEV listing lies between the 3 days and 14 days in the second row.

The response-time target is governance guidance, not a legal, compliance, or regulatory judgment.

## Using actual results in the PDCA cycle

For each Issue, the aggregation job records the starting point, detection, creation, and closing times, and the reason for closing (`resolved` for a fix, `vex_not_affected`, `vex_fixed`, `withdrawn`, `feed_version_delisted`, and `below_threshold`; six in all). The aggregation job saves run results append-only under `runs/`. Each record carries the hash of the previous record of the same month (`prev_record_sha256`), so an edited, removed, or replaced record is detected by the watchdog as a break in the chain (record format version 2). The result for fixes covers only Issues resolved by a fix, and is viewed in three stages.

- From detection to Issue creation
- From Issue creation to the fix PR
- From the PR to the merge

Vulnerability-fix PRs are not automerged, so waiting for human review can account for most of the fix time. The split into three is there to show where the delay is.

### Monthly review steps

1. Check: In the aggregation job's run results, check, per repository, the number of Issues left open past their fix deadline and the number of Issues opened in the run whose detection time exceeded 24 hours. Also look at the number left out because the starting point was unknown. For an Issue opened on a KEV listing alone, count a detection time over 24 hours as a "certain overrun" only when it is over 24 hours against the upper bound too. Count one that is over only against the lower bound separately, as "possibly missed". For entries read while the aggregation job was stopped, the upper bound can be later than the true publication time by up to the length of the stop (confirm the stop from the run results).
2. Check: See in which of the three stages the delay lies. If it is review waiting, suspect how people are assigned; if it is detection to creation, suspect the aggregation job's interval and feed fetch failures.
3. Act: When deadline overruns continue, decide whether to change the response-time target to fit reality or to fix the cause of the delay. If the Cooldown is the cause of the delayed fixes, review the Cooldown value.
4. Act: When you change a value, follow [Replacing the values with your own](#replacing-the-values-with-your-own) and fix the policy file and the numbers in this guide in the same PR.
5. Check the current version of references that carry a version or date: the Well-Architected Framework, SLSA, OpenVEX, the EPSS model, and Renovate.
6. Review the approved VEX documents ([Operating VEX](#monthly-review)).

Check corresponds to Well-Architected OPS09-BP01 (measure operations goals with metrics), and Act corresponds to OPS11-BP02 (identify preventive actions through post-incident analysis). See the [framework mapping](cyber-resilience-framework-mapping.md#best-practice-ids) for the mapping table; it is not copied here.

### Items to confirm in the pilot

The pilot period is counted from the run in which the aggregation job first produced the findings list for both repositories, and the default is 14 calendar days. During that period, the controls apply to two repositories only: this repository and the Hub. The false-positive rate is the number of Issues judged to be detector errors, divided by the number of Issues opened. If the period ends with fewer than 20 Issues opened, the same period can be extended (by 14 calendar days, up to 2 times, 42 calendar days in total).

The numerator is the sum of two counts: the Issues that a VEX approver judged `not_affected` with the justification `component_not_present`, and the Issues that the maintainer classified as detector errors. An Issue judged `fixed` or `affected`, and an Issue judged `not_affected` for another reason, are not counted as false positives; they are recorded as separate counts. A duplicate Issue (the side treated as a duplicate of another Issue) is not counted in the denominator either; only its number is recorded separately. The number of Issues not yet judged (including Issues that have only an `under_investigation` statement) is recorded separately and stays in the denominator.

While Issues not yet judged exceed 20% of the Issues opened, judge them first and calculate the rate afterwards (20% is a provisional value; hypothesis). While fewer than 20 Issues have been opened, record the counts only and do not calculate the rate. At the same time, decide whether to keep the fix target for High and above at 14 days or extend it to 30 days.

If 20 Issues are still not reached after the extensions, decide whether to move to the next group of repositories (the next batch) not from a rate but by the conditions in step 3, using the counts in step 1 and the manual review in step 2.
The decision record is a record that the maintainer keeps in one fixed place, appending dated entries. This guide does not fix the place (`open`). In it, write the decision to start the next batch or not, whether to keep the repositories already covered or roll them back, and whether to rebuild the detector, each with its reason. The criteria for starting the next batch are three: the limit of the false-positive rate, the limit of the number of repositories recorded as fetch failures, and whether the calling workflows have a CI failure. Write the limit of fetch failures and the CI-failure condition in the decision record before the pilot. Leave the limit of the false-positive rate undecided, and write in advance how it will be decided and where it is recorded; the pilot sets the value. If the fetch-failure limit or the CI-failure condition is not decided, or if the false-positive limit is still undecided when 20 Issues or more have been opened, do not start the next batch. If you did not write them before the pilot, restart the observation using only the Issues opened at or after the time you wrote the values, and keep that date and time in the decision record. The maintainer's list of operations is: enabling the ruleset, Code Owners, and Dependabot alerts on a repository where they were confirmed to be off, allowing auto-merge, preparing the VEX identity that opens VEX PRs, pushing a commit to the Hub's default branch at intervals of no more than 30 days, and running the check command `gh api 'repos/<Hub owner>/<Hub repository>/actions/workflows?per_page=100' --jq '.workflows[] | select(.state != "active" and .state != "deleted") | .name'`.

1. Record six counts: the Issues opened, the Issues classified as detector errors, the Issues judged `not_affected` for a reason other than `component_not_present`, the Issues judged `fixed`, the Issues judged `affected`, and the Issues not yet judged. An Issue classified as a detector error is counted once, as an error, whatever the state of its statement. The number of Issues opened equals the sum of the other five counts. Do not include a duplicate Issue in these six counts.
2. The maintainer reviews every opened Issue by hand, one at a time.
3. While fewer than 20 Issues have been opened, the next batch may start only when all six of these hold: there are 2 detector errors or fewer, no Issue is still unjudged, detector errors are fewer than half of the Issues opened (exactly half does not pass), the number of repositories recorded as fetch failures is within its limit, the calling workflows have no CI failure, and the settings in the maintainer's list of operations are confirmed. The 2 is a provisional value (hypothesis) that the pilot sets. If any one fails, do not start the next batch. The limit of the false-positive rate is not used while fewer than 20 Issues have been opened, because the rate is not calculated. Write in the decision record whether each of these six held, and the number of Issues not yet judged. The result of the rate-calculation tool shows the half-or-more condition as `errors_are_majority`; when it is true, do not proceed even if there are 2 detector errors or fewer.
   - Count the Issues not yet judged among the Issues cut off at the end of the observation period. An Issue opened after the end is not in this count; carry it over to the first record of the next observation as a number of Issues opened.
   - When Issues not yet judged are the only reason the next batch cannot start, do not extend the period. The maintainer finishes the judgments and then updates the decision record of step 3. Until it is updated, the next batch does not start. This wait does not count as an extension. While you wait, keep pushing to the Hub's default branch at intervals of no more than 30 days, and keep running the check command. If the Hub stays idle for 60 days, the aggregation job is disabled automatically and the observation stops without notice.
   - A statement that is `under_investigation` counts as not yet judged, also while you wait for an upstream response. Either move it to a state you can decide while waiting (`affected`, with a deadline), or do not proceed until it is decided. While you wait for the upstream response, keep the same push and check command.
   - When the only reason the next batch cannot start is a fetch failure, a CI failure in the calling workflows, or an unconfirmed setting, fix the cause. Then do not restart the observation: update the decision record of step 3 with what you fixed and when, and evaluate again whether to proceed. This wait counts neither as an extension nor as a restart. While you wait, keep the same push and check command. If you cannot fix the cause, write in the decision record whether to keep the repositories already covered or roll them back.
   - When no Issue was opened, write 0 as the number of Issues opened. With 0 Issues, neither the count of errors nor "fewer than half" can be judged, and even if the totals say that the conditions hold, 0 Issues is not evidence that they hold, so do not use it as the reason to proceed. If no Issue was opened even after the extensions are used up, run the false-negative check. In at least one repository of that batch (in a restart, a repository the fixed detector applies to), place one throwaway dependency with a known vulnerability (not KEV-listed, CVSS High), write in the decision record whether an Issue was opened within 24 hours, and remove the dependency afterwards. If the check succeeded, and the three other criteria (the fetch-failure limit, no CI failure, confirmed settings) also hold, the maintainer may decide to proceed. Do not count the check's Issue, and do not pass it to the rate calculation. If no Issue was opened by the check, fix the detector and count it as a restart in step 4.
4. If there are 3 or more detector errors, detector errors are half or more of the Issues opened, or the false-positive rate is over the limit at 20 Issues or more, do not start the next batch. If no Issue was opened after the extensions are used up, and the false-negative check of step 3 has not succeeded, do not start the next batch: fix the detector and restart. If it succeeded, the maintainer decides under the conditions of step 3. When there are errors, the maintainer classifies the cause of each error, judges whether the same cause repeats, and records it. Whether the cause repeats or not, fix the detector for each cause and then restart the observation of the pilot or of that batch.
   - Count the restarted observation period from the run in which the aggregation job first used the fixed detector. Its length is 14 calendar days for the pilot and 7 calendar days for a batch. The denominator is only the Issues opened at or after that time. Do not count the Issues opened in the previous observation, even if they are still open. In a batch observation, count only the Issues opened in that batch's repositories, and record the Issues of earlier repositories as a separate number. In the record of the restart, write the counts of the previous observation and the number of Issues that were left out of the denominator.
   - If no Issue was opened in the restarted observation, there is no evidence that the fixed detector was checked. Follow the handling of 0 Issues in step 3 and do not proceed. You may use the extension for 0 Issues, but it counts toward the number of extensions (at most 2 for the pilot; for a batch, only when no Issue was opened). After the extensions are used up, follow the false-negative check in step 3.
   - A restart does not count as an extension, and an extension does not count as a restart. Restart at most 3 times (a provisional value; hypothesis, to be set by the pilot). If the next batch still cannot start after the third restart, stop the observation. The maintainer decides whether to keep the repositories already covered or to roll them back (to return their settings to the previous state), and whether to rebuild the detector, and writes the reasons in the decision record. A rebuilt detector is a new detector: count its restarts from 0, and write in the decision record that you started the count again.
5. If 20 Issues are still not reached after the extensions (including when no Issue has been opened), do not calculate the rate, and write in the decision record that 20 was not reached. If no Issue was opened even after the extensions are used up, write the result of the false-negative check in step 3 in the decision record, and then decide whether to proceed or stop.
When the number of new Issues in one run for one repository reaches the limit and the next batch is stopped, classify the cause as the first bulk opening or continuing opening, and record it. The first bulk opening is the case where the limit was reached in the first run of that repository; every other case is continuing opening (a provisional classification; hypothesis). For the first bulk opening, judge step 3 after all of the Findings that went into the summary Issue beyond the limit have been opened individually in later runs. Count only individually opened Issues in the number of Issues opened. For continuing opening, do not judge step 3: write in the decision record whether to keep the repositories already covered or roll them back.

## Relationship to Well-Architected

The correspondence between this guide and Well-Architected best-practice IDs is not the result of an AWS Well-Architected review, and it is not an AWS endorsement. It reflects a reading of the best-practice pages and a judgment that the components address the same topic. The mapping table is placed only in the [framework mapping](cyber-resilience-framework-mapping.md#best-practice-ids), and this guide does not copy it. The version referred to is v13 (2024-11-06) [G18], [G19].

A service owner can review their own workload with the [AWS Well-Architected Tool](https://aws.amazon.com/well-architected-tool/) and record decisions and improvements. The mapping to NIST CSF 2.0 is in a [section](cyber-resilience-framework-mapping.md#mapping-pdca-and-accountability-to-csf-20) of the same mapping, and it is not a NIST endorsement. Both mappings are governance guidance, not legal, compliance, or regulatory judgments.

## References

The documents this guide relies on are listed in this order: name (the original title given by the publisher), publisher, publication date and version, URL, the date checked (the day the content of that URL was confirmed), and evidence label. Where no date is shown, that is stated. Names are kept in the original title in both the Japanese and English versions. Dates are in Japan time, and a publication date is the date shown on the page. The numbers match the `[Gn]` marks in the text. G is the number in this adoption guide, a numbering separate from the `[n]` of the overall plan for the three pillars. A document cited with `[E-nnn]` has the same URL in the source field of [evidence-ledger.json](../agent/evidence-ledger.json).

| No. | Name | Publisher | Date and version | URL | Date checked | Evidence |
|---|---|---|---|---|---|---|
| G1 | Minimum Release Age | Renovate | No date shown | [docs.renovatebot.com](https://docs.renovatebot.com/key-concepts/minimum-release-age/) | 2026-11-13 | documented |
| G2 | Configuration Options | Renovate | No date shown | [docs.renovatebot.com](https://docs.renovatebot.com/configuration-options/) | 2026-11-13 | documented |
| G3 | config (npm CLI v11) | npm | v11 | [docs.npmjs.com](https://docs.npmjs.com/cli/v11/using-npm/config) | 2026-11-13 | documented |
| G4 | OpenVEX Specification | OpenVEX | v0.2.0 | [github.com/openvex](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md) | 2026-11-10 | documented |
| G5 | Using artifact attestations | GitHub | No date shown | [docs.github.com](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations) | 2026-11-10 | documented |
| G6 | gh attestation verify | GitHub | No date shown | [cli.github.com](https://cli.github.com/manual/gh_attestation_verify) | 2026-11-10 | documented |
| G7 | Build: Track Basics | OpenSSF SLSA | v1.2 | [slsa.dev](https://slsa.dev/spec/v1.2/build-track-basics) | 2026-11-12 | documented |
| G8 | REST API endpoints for software bill of materials (SBOM) | GitHub | API version 2026-03-10 | [docs.github.com](https://docs.github.com/en/rest/dependency-graph/sboms) | 2026-11-13 | documented |
| G9 | Exporting SBOMs with Amazon Inspector | AWS | No date shown | [docs.aws.amazon.com](https://docs.aws.amazon.com/inspector/latest/user/sbom-export.html) | 2026-11-13 | documented |
| G10 | Amazon Inspector integration with AWS Security Hub CSPM | AWS | No date shown | [docs.aws.amazon.com](https://docs.aws.amazon.com/inspector/latest/user/securityhub-integration.html) | 2026-11-13 | documented |
| G11 | Amazon Inspector Lambda standard scanning | AWS | No date shown | [docs.aws.amazon.com](https://docs.aws.amazon.com/inspector/latest/user/scanning_resources_lambda.html) | 2026-11-13 | documented |
| G12 | Scanning AWS Lambda functions with Amazon Inspector | AWS | No date shown | [docs.aws.amazon.com](https://docs.aws.amazon.com/inspector/latest/user/scanning-lambda.html) | 2026-11-13 | documented |
| G13 | AWS Security Hub FAQs | AWS | No date shown | [aws.amazon.com](https://aws.amazon.com/security-hub/faqs/) | 2026-11-13 | documented |
| G14 | Software bill of materials (AWS Security Hub User Guide) | AWS | No date shown | [docs.aws.amazon.com](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-v2-sbom.html) | 2026-11-13 | documented |
| G15 | AWS Security Hub now provides an SBOM inventory for your compute resources | AWS | 2026-11-06 | [aws.amazon.com](https://aws.amazon.com/about-aws/whats-new/2026/11/security-hub-sbom-inventory/) | 2026-11-12 | documented |
| G16 | AWS Security Hub Pricing | AWS | No date shown | [aws.amazon.com](https://aws.amazon.com/security-hub/pricing/) | 2026-11-12 | documented |
| G17 | GetSoftwareV2 (AWS Security Hub API Reference) | AWS | No date shown | [docs.aws.amazon.com](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetSoftwareV2.html) | 2026-11-13 | documented |
| G18 | AWS Well-Architected Framework | AWS | v13 (2024-11-06) | [docs.aws.amazon.com](https://docs.aws.amazon.com/wellarchitected/latest/framework/welcome.html) | 2026-11-13 | documented |
| G19 | What is AWS Well-Architected? | AWS | 2026-10-01 (the page's Last updated) | [docs.aws.amazon.com](https://docs.aws.amazon.com/wellarchitected/latest/userguide/well-architected.html) | 2026-11-10 | documented |
| G20 | Well-architected best practices for software supply chain security | AWS Security Blog | The publication date could not be obtained | [aws.amazon.com](https://aws.amazon.com/blogs/security/well-architected-best-practices-for-software-supply-chain-security/) | 2026-11-10 | documented (the blog's statement). The publication date is open |
| G21 | OpenSSF Malicious Packages | OpenSSF | No date shown | [github.com/ossf](https://github.com/ossf/malicious-packages) | 2026-11-10 | documented |
| G22 | OSV.dev Data Sources | OSV.dev | No date shown | [google.github.io](https://google.github.io/osv.dev/data/) | 2026-11-10 | documented |
| G23 | Known Exploited Vulnerabilities Catalog | CISA | catalogVersion 2026.11.09 | [cisa.gov](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | 2026-11-10 | verified (fetched once) |
| G24 | GET /epss (FIRST.Org REST API Documentation) | FIRST | The API is shown as BETA | [api.first.org](https://api.first.org/epss/) | 2026-11-12 | documented. The response shape is verified (once) |
| G25 | Cyber Resilience Act - Reporting obligations | European Commission | No date shown | [digital-strategy.ec.europa.eu](https://digital-strategy.ec.europa.eu/en/policies/cra-reporting) | 2026-11-14 | documented |
| G26 | MCP Security Crisis: Systemic Design Flaws in AI Agent Infrastructure | Cloud Security Alliance (CSAI Foundation) | 2026-05-04 (research note; the document states that it was produced with AI assistance and has not had formal CSA review) | [labs.cloudsecurityalliance.org](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/05/CSA_research_note_MCP_security_crisis_20260504-csa-styled.pdf) | 2026-11-10 | documented |
| G27 | ★3・★4要求事項・評価基準（Ver.1.1:2026年10月28日） (Japanese only) | METI | Ver 1.1, 2026-10-28 | [xlsx](https://www.meti.go.jp/policy/netsecurity/docs/scs/SCS-400-criteria-v1.1.xlsx) | 2026-11-12 | documented |
| G28 | Cyber Essentials: Requirements for IT Infrastructure v3.3 | NCSC (UK National Cyber Security Centre) | v3.3, April 2026 | [ncsc.gov.uk](https://www.ncsc.gov.uk/files/cyber-essentials-requirements-for-it-infrastructure-v3-3.pdf) | 2026-11-13 | documented (the section read is Security Update Management) |
| G29 | BOD 26-04: Prioritizing Security Updates Based on Risk | CISA | 2026-06-10 | [cisa.gov](https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk) | 2026-11-13 | documented (Table 1 is an image, so it was read from the image) |
| G30 | Reuse workflows | GitHub | No date shown | [docs.github.com](https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows) | 2026-11-14 | documented |
| G31 | Immutable releases | GitHub | No date shown | [docs.github.com](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases) | 2026-11-14 | documented |
| G32 | Secure use reference | GitHub | No date shown | [docs.github.com](https://docs.github.com/en/actions/reference/security/secure-use) | 2026-11-14 | documented |
| G33 | Events that trigger workflows | GitHub | No date shown | [docs.github.com](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows) | 2026-11-14 | documented (the section read is `schedule`) |

# Supply-Chain Use Cases and Options (Including Storage)

> **Overview**
>
> This document describes how an organization that runs ONTAP or Amazon FSx for NetApp ONTAP (FSx for ONTAP hereafter) can manage the software supply chain of the whole system, storage included. It is organized as 11 use cases (A1 to D1). AWS services, SaaS products and standards are listed with the situations they suit and their trade-offs at the same level of detail, without a ranking. It states no prices. Research and confirmation date: 2026-11-17 (Japan time).

The overall position of this document, and why the data is placed on FSx for ONTAP, are in the [Cyber Resilience Programme](cyber-resilience-programme.md#why-fsx-for-ontap-appears-in-a-whole-system-implementation-pattern).

## What this document lets you decide

This document helps you decide, for your own environment (on-premises ONTAP, a new FSx for ONTAP, or an existing FSx for ONTAP), which parts of supply-chain management this repository's mechanisms cover and which parts you complement with AWS services or SaaS products. The procedures and numbers are defined in the [Supply-Chain Adoption Guide](supply-chain-adoption-guide.md) and the policy file ([`supply-chain-policy.json`](../agent/supply-chain-policy.json)), and are not copied here. This document only maps each situation to usage and options.

This document does not cover the following.

- Configuring ONTAP's own features (ARP, FPolicy, SnapLock). It links to the existing documents only
- Prices
- Firmware and device dependencies at sites or gateways. Only the code on and next to ONTAP is in scope
- Judgments about regulatory or legal conformance. It is governance guidance, not a legal or compliance judgment
- The second and third pillars ([overall plan for the three pillars](cyber-resilience-programme.md))

Each use case begins with who decides and when it is done, in role names. They are a guide for using this repository's mechanisms; map them to your own organization's roles.

Start from the row that is closest to your situation.

| Situation | Sections to read |
|---|---|
| Match on-premises ONTAP versions against advisories and plan updates | A1, A2 |
| Manage the dependencies of your own code that runs on or next to ONTAP | A3, B2, C2 |
| Connect ransomware protection with vulnerability management | A4 |
| Create a new FSx for ONTAP file system, or already run one | B1 to B3, C1 to C3 |
| Collect findings in a SIEM or a ticketing system | D1 |

Each use case table has a column for the source and the confidence. Confidence is written in the following four categories.

| Category | Meaning |
|---|---|
| Stated in official docs | The relevant passage of a vendor or standards-body document was read |
| Excerpt only | Only a search-result excerpt was read, not the full text |
| Inference | This project's reasoning from facts that were read. The vendor does not state it |
| Not confirmed | Could not be read, or no statement was found. Finding no statement is not proof that none exists |

Labels such as `[R01]` in the sources refer to the numbers in the [References](#references) at the end.

A row that describes this repository's own behavior gives a link to the adoption-guide section it rests on, in place of a confidence category. When more than one category applies to a row, it is written as "category (subject)", with one of the four categories for each subject.

## The three layers of the supply chain, including storage

The management tools differ by layer.

| Layer | What it contains | Who updates the version | Where to manage it |
|---|---|---|---|
| ONTAP itself | The ONTAP software that NetApp ships | The user on premises. For FSx for ONTAP, AWS applies patches and the user chooses the maintenance window time [R07] | NetApp security advisories, Digital Advisor, the AWS maintenance window |
| The user's code on or next to ONTAP | Lambda, containers, IaC, ONTAP REST clients, operations scripts | The user | Dependency graph, SBOM, Dependabot and Renovate, Amazon Inspector |
| The development flow | Repositories, CI, distributed artifacts | The user | Branch and tag rulesets, signing, provenance attestations, immutable releases |

This repository's first-pillar mechanisms mainly target the second and third layers. The first layer is a manual match that uses the component register (the file is [`infrastructure-component-ledger.json`](../agent/infrastructure-component-ledger.json)) and a procedure document (A1, A2, B1).

## List of use cases

| ID | Situation | What is managed |
|---|---|---|
| A1 | Match the running version of on-premises ONTAP against NetApp security advisories | ONTAP version, CVEs in advisories |
| A2 | Plan and run an update (patch or major version) of on-premises ONTAP | ONTAP version, pre-update checks |
| A3 | Manage the dependencies of your own apps, scripts and containers that run on or next to ONTAP | Dependency packages, container images, IaC |
| A4 | Connect ransomware protection (ARP and others) with vulnerability management | The list of vulnerabilities confirmed as exploited, and the state of protection features |
| B1 | Divide AWS's scope and your own when you create a new FSx for ONTAP | Maintenance window, confirming the ONTAP version |
| B2 | Manage the dependencies of Lambda, containers and IaC next to FSx for ONTAP from the start | Dependencies, SBOM, scanning |
| B3 | Put change provenance and deployment safeguards in place from the start | Signing, provenance attestations, staged deployment |
| C1 | Replace the A1 and A2 procedures for FSx for ONTAP in an existing operation that moved from on premises | Matching and update procedures |
| C2 | Take stock of the dependencies of ONTAP REST clients and operations scripts that already run | Dependencies of existing code, adding an SBOM later |
| C3 | Cover both on-premises ONTAP and FSx for ONTAP during a migration | Two management surfaces side by side |
| D1 | Collect findings in one place (SIEM, ticketing) | Format and delivery path of findings |

## On-premises ONTAP (A1 to A4)

### A1 Matching the running version against security advisories

Who decides: the storage administrator. Done when: every running cluster version is in the [component register](../agent/infrastructure-component-ledger.json), each row has a match date, and its status is something other than "判定保留" (undetermined).

This fits when you operate ONTAP yourself and want to confirm whether the running version is covered by a NetApp security advisory. NetApp publishes the vulnerabilities it has validated as advisories with CVE IDs. Advisories can be filtered by keyword, product and severity, and subscribed to as RSS 2.0 [R01][R02].

In this repository, a person records the version in the [infrastructure component register](../agent/infrastructure-component-ledger.json) and matches it against the advisory RSS. A person makes the final decision, and rows whose match date is more than 90 days old become due for a new match (step 6 of [Inventory](supply-chain-adoption-guide.md#inventory)). The version upgrade as a response to an advisory is described in the [ONTAP upgrade procedure](../ontap-native/ontap-upgrade-for-security-advisories.md).

| Option | Fits when | Trade-off | Source and confidence |
|---|---|---|---|
| Read the advisory list and RSS by hand | A small number of systems. A closed network that cannot send telemetry | Matching against your own versions is manual | Stated in official docs [R01][R02] |
| Digital Advisor | You send AutoSupport to NetApp and hold a support contract | Requires AutoSupport transmission and support entitlement | Stated in official docs [R03] |
| Risk display in ONTAP System Manager | You want to see it in the everyday management screen | Depends on the same information source as Digital Advisor | Excerpt only [R04] |
| NetApp SBOM and VEX | You want to match ONTAP components in a machine-readable way | No statement that they are provided was found in the pages read. Whether they are provided has not been confirmed | Not confirmed [R02] |

### A2 Planning and running an ONTAP update

Who decides: the storage administrator and the change approver. Done when: the version after the update is in the register, the result of the pre-update check is kept, and the advisories have been matched again against the new version.

This fits when you raise the ONTAP version in response to an advisory or to the end of a support period. NetApp advises applying non-critical patch releases every 3 to 6 months and critical ones as soon as possible. A new release has full support for 3 years, and vulnerability notification is included in the full-support period [R05]. The support-level table in NetApp's document was read from the plain text of the page, not from its rendered layout, so the correspondence between its columns (the periods) is inference. For running the update, NetApp advises using automated nondisruptive upgrade (ANDU) [R06].

This repository collects the procedure to use at the planning stage in the [ONTAP upgrade procedure](../ontap-native/ontap-upgrade-for-security-advisories.md). How this applies to FSx for ONTAP is covered in C1.

| Option (preparation method) | Fits when | Trade-off | Source and confidence |
|---|---|---|---|
| Upgrade Advisor | You have an active SupportEdge contract for Digital Advisor and want to proceed in the UI. Smaller environments | Requires the contract and cloud connectivity | Stated in official docs (when it fits), inference (trade-off) [R06] |
| Upgrade Health Checker | No contract, a closed network, or you want to build it into automation. Large or complex environments | You interpret the results yourself | Stated in official docs (when it fits), inference (trade-off) [R06] |
| Manual preparation | Works in any environment | Many items to check, and you must prevent oversights yourself | Inference [R06] |

### A3 Managing the dependencies of your own code on or next to ONTAP

Who decides: the repository maintainer. Done when: a dependency list can be produced for each target repository, each Issue that meets the opening condition has an owner and a deadline, and the wait before taking newly published versions is configured.

This fits when you want to manage the dependencies of code you wrote (ONTAP REST clients, operations scripts, containers, IaC), even when no SBOM for ONTAP itself is available. The user can manage these dependencies (inference).

In this repository, [Inventory](supply-chain-adoption-guide.md#inventory) keeps the list of dependencies, [Detection and prioritization](supply-chain-adoption-guide.md#detection-and-prioritization) turns findings into Issues, and [Defending at intake](supply-chain-adoption-guide.md#defending-at-intake) delays taking in freshly published versions. Within the first pillar, Amazon Inspector and AWS Security Hub are not enabled.

| Option | Fits when | Trade-off | Source and confidence |
|---|---|---|---|
| GitHub dependency graph and SBOM export | You want to see dependencies per repository | Needs the dependency graph enabled, and covers supported ecosystems only. Dependents are not in the SBOM | Stated in official docs [R21] |
| Cooldown in Dependabot and Renovate (a wait before taking in freshly published versions) | You do not want to take in freshly published versions | Fixed versions are also not taken in during the Cooldown. Dependabot's Cooldown does not apply to security updates. With Renovate, there is one observation of a new tag that points to a back-dated commit becoming an update candidate without the wait. For third-party Actions, do not count the Cooldown as a defense ([adoption guide](supply-chain-adoption-guide.md#limit-of-the-cooldown-for-github-actions)) | Stated in official docs (specification) [R22][R23] |
| Amazon Inspector SBOM export | You want to continuously watch the dependencies of EC2, ECR and Lambda on AWS, or hand an SBOM to an audit or a business partner | Limited to resources on AWS. A dependency declared with a version range or a dynamic reference is listed as an unresolved hash, not as a name and version. An SBOM lists the components and versions you use, so decide whom you hand it to and how much. The format and required fields for a business partner follow that partner's requirements | Stated in official docs (the feature) [R11][R12], inference (how much to hand over) |
| OpenSSF Malicious Packages (OSV format) | You want to detect intentionally malicious dependencies, not vulnerabilities | The completeness of the registered reports is unknown | Excerpt only [R27][R28] |

### A4 Connecting ransomware protection and vulnerability management

Who decides: the security owner and the storage administrator. Done when: the inputs used for prioritization are chosen, and the place to check each protection feature setting (the links above) is decided.

This fits when protection features such as ARP are in place and you want to connect vulnerability management around them. Vulnerability management reduces the entry points, while ARP and similar features reduce the damage after an intrusion, so their roles differ (inference). The configuration of ONTAP's own features is in the existing documents.

- [ARP configuration](../ontap-native/arp-configuration.md)
- [FPolicy configuration](../ontap-native/fpolicy-configuration.md)
- [SnapLock configuration](../ontap-native/snaplock-configuration.md)
- [Tamperproof Snapshot configuration](../ontap-native/tamperproof-snapshot.md)
- [Cyber resilience framework mapping](cyber-resilience-framework-mapping.md)

There are four inputs you can use to prioritize vulnerabilities. This repository opens an Issue when any of these holds: CVSS severity is High or above, the vulnerability is listed in KEV, or the package is malicious. EPSS is used for display only ([Detection and prioritization](supply-chain-adoption-guide.md#detection-and-prioritization)).

| Option (input) | Fits when | Trade-off | Source and confidence |
|---|---|---|---|
| CISA KEV | You want "is it being exploited now" to drive priority | Many entries have `Unknown` in the field that shows ransomware use, so it cannot be the deciding factor. The count changes with the catalog version | Stated in official docs [R29] |
| FIRST EPSS | You want to rank by likelihood of exploitation | A probability of exploitation within 30 days, not a fact of exploitation. It is meant to be used with KEV and CVSS | Stated in official docs [R30] |
| Vendor severity (CVSS) | The severity that the vendor advisory assigns is enough | Medium or lower findings with evidence of exploitation are put off | Stated in official docs (the severity display), inference (the postponement) [R01] |
| Amazon Inspector vulnerability intelligence | You want to see the KEV addition date and due date in the findings view on AWS | Not every CVE has the information. Limited to resources that Inspector covers | Stated in official docs [R13] |

## New FSx for ONTAP users (B1 to B3)

### B1 Dividing AWS's scope and your own

Who decides: the storage administrator who holds AWS-side permissions. Done when: the maintenance window time is set, and someone owns recording the application date and the version after application in the register.

This fits when you are about to create an FSx for ONTAP file system and want to separate what AWS handles for version updates from what you do. For FSx for ONTAP, AWS performs maintenance and updates of the file system on a regular basis. It applies them to one side of the HA pair at a time and fails over to the partner beforehand, so an I/O pause of under 60 seconds can occur. On both Single-AZ and Multi-AZ file systems, the HA pair fails over to the standby for planned maintenance. The two do not differ for planned maintenance; failover caused by an Availability Zone outage applies to Multi-AZ file systems only [R33]. For NFS and SMB clients, AWS describes the failover as transparent. For iSCSI and NVMe/TCP, it depends on client-side multipathing [R33]. The design of application-side retries and timeouts is outside this document and has not been confirmed. You choose the start time of the maintenance window at creation and can change it later. A window is required at least once every 14 days, and if no window falls within 14 days after a patch is released, AWS proceeds with maintenance [R07]. The sensitivity of the data, the organization's requirements and the law are the user's responsibility [R09]. For the management entry points, the documentation lists both AWS-side tools and NetApp-side tools (ONTAP CLI, REST API and others) [R08].

The user's work shifts from "match and hold back the update" to "decide the time of application, then confirm the version and advisories after it is applied" (inference). What the user sets is the start time of the maintenance window (`WeeklyMaintenanceStartTime`). A window is required at least once every 14 days; without one in that period, patches are applied automatically [R07]. The file system create and update APIs have no field for the ONTAP version, and `OntapConfiguration` in `DescribeFileSystems` does not return it (the three API reference pages read, 2026-11-17) [R36][R37] [E-058]. To learn the version, read `GET /api/cluster` in the ONTAP REST API [R35].

In this repository, the ONTAP version and the FSx for ONTAP deployment type are recorded in the [infrastructure component register](../agent/infrastructure-component-ledger.json). The [ONTAP upgrade procedure](../ontap-native/ontap-upgrade-for-security-advisories.md) targets self-managed ONTAP and is not applied to FSx for ONTAP.

| Option | Fits when | Trade-off | Source and confidence |
|---|---|---|---|
| Maintenance window design | You want application at a quiet time for the business | There is a 14-day upper bound. Each application can cause an I/O pause of under 60 seconds. AWS's documents do not describe recording the application date and the version after application in the register | Stated in official docs (the window, 14 days, 60 seconds) [R07], inference (recording before and after) |
| AWS Config | You want to keep a configuration change history and evaluate deviations | What is recorded depends on the resource type. Which FSx for ONTAP settings are recorded has not been confirmed | Stated in official docs (overview), not confirmed (the range of settings recorded) [R17] |
| AWS Security Bulletins | You want to subscribe to AWS security information | Whether FSx for ONTAP is covered has not been checked. The RSS feed keeps only the last 30 days | Stated in official docs (the page description), not confirmed (FSx for ONTAP coverage) [R10] |
| NetApp security advisory RSS | You want to confirm whether your environment is affected, and whether the version caught up after application | Whether AWS documents how to check the version has not been confirmed. The match is a manual procedure | Inference (the match is a manual procedure), not confirmed (whether AWS documents how to check the version) [R01] |

### B2 Managing the dependencies of Lambda, containers and IaC from the start

Who decides: the repository maintainer. Done when: dependencies are pinned, at least one path for scanning or SBOM export works, and the recipient of the results is decided.

This fits when you place Lambda, containers and IaC next to FSx for ONTAP and want pinning, scanning and SBOM export from the start. You can begin while there is little to detect (inference).

This repository's mechanisms are in [Inventory](supply-chain-adoption-guide.md#inventory) and [Defending at intake](supply-chain-adoption-guide.md#defending-at-intake). Amazon Inspector and AWS Security Hub are not enabled in the first pillar, and this document does not cover how to enable them or what they cost. If you use them, check the billing unit and the number of target resources on each service's pricing page before enabling.

| Option | Fits when | Trade-off | Source and confidence |
|---|---|---|---|
| Amazon Inspector | You want to continuously watch the dependencies of compute resources on AWS | First-time activation enables standard scanning of EC2, ECR and Lambda. Lambda code scanning and Code Security are enabled separately. The ECR rescan period defaults to 7 days when you activate ECR scanning on or after 2026-10-15. An account that already has it activated keeps its current setting | Stated in official docs [R11][R32] |
| AWS Security Hub SBOM inventory | You want to look up where a package is across multiple accounts | What you can see is limited to the resources Inspector covers. Reflection can take hours. It is a different service from AWS Security Hub CSPM | Stated in official docs [R15] |
| Python libraries in notebooks and jobs, and the source of pretrained models | You run analytics or AI processing that reads data on the storage | Trusting the source and pinning with a lock file are the user's work. Libraries may be visible in the repository's dependency graph. Whether model weights appear in an SBOM has not been confirmed | Not confirmed |
| AWS CodeArtifact package origin controls | You use internal and public packages together | The default is decided by the path through which the first version of a package was added. The setting must be checked for each exception package | Stated in official docs [R19] |
| GitHub dependency graph with Renovate and Dependabot | You want dependency updates as pull requests per repository | Fixed versions are also held back during the Cooldown. Security updates take a different path | Stated in official docs [R21][R22][R23] |

### B3 Change provenance and deployment safeguards

Who decides: the repository maintainer. Done when: the mechanism for each path to protect is chosen, and the verifying side has a procedure. If you adopt staged deployment, include one real deployment in which an alarm-triggered rollback was confirmed.

This fits when you want signing, provenance attestations and staged deployment from the start.

In this repository, the procedures are in [Verifying provenance](supply-chain-adoption-guide.md#verifying-provenance) and [Loosely coupled updates](supply-chain-adoption-guide.md#loosely-coupled-updates). The reference implementation of the Lambda canary deployment is in the [template](../../templates/event-driven.yaml). On 2026-11-17 in ap-northeast-1, the canary-related resources of the template (the function, its alias, the deployment preference, the alarms and the PreTraffic hook) were deployed on their own, and each behaviour was checked once. On a normal update, the alias sent 10% of traffic to the new version for 10 minutes and then moved to it. With a version that fails only on real traffic, the new-version errors alarm went to ALARM, CodeDeploy stopped and the alias went back to the previous version. In that run, the way the template referred to `ExecutedVersion` was not resolved by the SAM transform and the deployment failed, so the reference was rewritten. Rollback driven by the FailedRecords, Duration or Throttles alarm alone, a failing PreTraffic hook, and traffic arriving through SQS were not tried.

| Option | Fits when | Trade-off | Source and confidence |
|---|---|---|---|
| AWS Signer | You do not want to run unsigned code (Lambda code packages, container images) | Needs signing key management and a design of who may sign. A signature confirms the publisher and that the artifact is unmodified, not that it is safe | Stated in official docs [R18] |
| GitHub artifact attestations | You want artifact origin to be verifiable | Has no effect unless someone checks it. It ties the artifact to the source and the build procedure, and is not a guarantee of safety | Stated in official docs [R24] |
| GitHub immutable releases | You want to prevent release artifacts from being replaced | Prepare the assets before publishing. Only the tag and the assets are locked | Stated in official docs [R25] |
| Staged deployment with AWS SAM and CodeDeploy | You want to roll out dependency updates to production in stages | If the alarm design is weak, the rollback does not work. The first deployment takes two steps | Stated in official docs [R20] |
| GitHub rulesets | You want to control the paths by which changes are made | Organization-wide rulesets are for the GitHub Enterprise plan. When rulesets overlap, the strictest one applies | Stated in official docs [R26] |

## Existing FSx for ONTAP users (C1 to C3)

### C1 Replacing the on-premises procedures for FSx for ONTAP

Who decides: the storage administrator. Done when: every register row is marked as updated by you or updated by AWS, the matching procedure is written in its replaced form, and the handling of the rows not confirmed (pre-update checks, version choice) is decided.

This fits when you moved from on-premises ONTAP to FSx for ONTAP and the A1 and A2 operations remain. The replacement is outlined in the following table, and it includes rows that have not been confirmed.

| Procedure | On-premises operation | Replacement for FSx for ONTAP | Source and confidence |
|---|---|---|---|
| Matching against advisories | Read advisories and plan the update | Becomes checking whether you are affected and whether the version caught up after application | Inference [R07] |
| Planning and running updates | Decide the version and timing yourself and run it | Becomes choosing the maintenance window time and checking after application | Stated in official docs (the window), inference (the replacement) [R07] |
| Pre-update checks | Upgrade Advisor, Upgrade Health Checker | Whether they can be used with FSx for ONTAP has not been confirmed | Not confirmed [R06] |
| Reading the current version | Read the version from the cluster management interface | ONTAP REST `GET /api/cluster` returns `version`. The FSx for ONTAP management endpoint is reached from inside the VPC as `fsxadmin` | Stated in official docs (the `version` field) [R35]. A read on FSx for ONTAP is recorded in this repository's [snapshot](../ontap-native/ontap-command-api-snapshot.md) (one file system, SINGLE_AZ_1, ap-northeast-1, ONTAP 9.18.1P6, 2026-11-04, one read) |
| Choosing the version | Choose the target version | The user sets the maintenance window time; the create and update APIs have no field for the version (the three API reference pages read) | Stated in official docs [R07][R36][R37] |

### C2 Taking stock of dependencies in existing operations scripts and ONTAP REST clients

Who decides: the repository maintainer. Done when: a dependency list can be produced for every repository of the existing scripts and ONTAP REST clients, and the handling of unpinned dependencies is decided.

This fits when you take stock, after the fact, of the dependencies of operations scripts and ONTAP REST clients that already run. It includes finding dependencies that are not pinned.

In this repository, follow the steps in [Inventory](supply-chain-adoption-guide.md#inventory) and [Choosing among inventory options](supply-chain-adoption-guide.md#choosing-among-inventory-options).

| Option | Fits when | Trade-off | Source and confidence |
|---|---|---|---|
| GitHub dependency graph and SBOM export | You want to add an SBOM to an existing repository later | Needs the dependency graph enabled, and covers supported ecosystems only. The format is SPDX | Stated in official docs [R21] |
| Amazon Inspector SBOM export | You want the composition of deployed Lambda functions and ECR images, or want to find unpinned dependencies | Unpinned dependencies are listed as "unresolved hashes". Vulnerability detection runs on dependencies whose name and version are known. The formats are CycloneDX 1.4 and SPDX 2.3 compatible | Stated in official docs [R12] |
| AWS Security Hub SBOM inventory | You want to look up where a package and version are in the organization | The response fields are name, type, version and count, so it is not directly comparable with the purl in a repository SBOM [E-053] (see [Choosing among inventory options](supply-chain-adoption-guide.md#choosing-among-inventory-options) in the adoption guide) | Stated in official docs [R15] |
| SBOM generation tools (Trivy, Syft with Grype, OSV-Scanner) | You want to choose the generation tool yourself | The constraints of each tool are in [Choosing an SBOM generation tool](supply-chain-adoption-guide.md#choosing-an-sbom-generation-tool) in the adoption guide | Adoption guide ([Choosing an SBOM generation tool](supply-chain-adoption-guide.md#choosing-an-sbom-generation-tool)) |

### C3 Running on-premises ONTAP and FSx for ONTAP side by side during a migration

Who decides: the storage administrator. Done when: every register row is classified by who updates it, and rows for finished migrations are removed.

This fits when you must cover both on-premises ONTAP and FSx for ONTAP in the middle of a migration. The migration method itself is outside this document.

In this repository, the rows of the [infrastructure component register](../agent/infrastructure-component-ledger.json) are recorded separately for what you update yourself and what AWS updates (inference).

| What to look at | On-premises ONTAP | FSx for ONTAP | Source and confidence |
|---|---|---|---|
| Updating the ONTAP version | The user runs it | AWS applies it in the maintenance window | Stated in official docs [R07] |
| Checking advisories | Match the version and plan the update | Check the impact, and check the version after application (C1) | Inference [R01] |
| Management entry points | ONTAP CLI, REST API, System Manager and others | Both AWS-side tools and NetApp-side tools | Stated in official docs [R08] |
| Separation in the register | Rows the user updates | Rows AWS updates | Inference |
| Guest OS of hosts that connect to ONTAP, and migration or monitoring agents | The user manages patches and versions | The user manages patches and versions. It is a path separate from the FSx for ONTAP maintenance window | Inference |

## Collecting findings (D1)

### D1 Collecting findings in a SIEM or ticketing system

Who decides: the security owner. Done when: the place for findings is decided, and at least one path that assigns an owner and a deadline works.

This fits when you want to collect findings in one place and track them with an owner and a due date. You decide the format and the delivery path.

This repository's aggregation job opens an Issue per repository ([Detection and prioritization](supply-chain-adoption-guide.md#detection-and-prioritization)). The side that sends audit logs to a SIEM is in [FSx for ONTAP Observability Integrations](https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations) (see [Companion repository integration](companion-repos-integration.md)).

| Option | Fits when | Trade-off | Source and confidence |
|---|---|---|---|
| Amazon EventBridge (Inspector events) | You want to route findings into your own tickets or notifications | You design the rules and targets yourself. Findings from an on-demand machine-image scan are output only to EventBridge, and appear neither in the console nor in Security Hub CSPM | Stated in official docs [R14] |
| AWS Security Hub and AWS Security Hub CSPM | You want an overview of findings across multiple accounts | The two are different services. CSPM mainly checks whether AWS settings meet a standard, and its main purpose is not vulnerability management of software dependencies | Stated in official docs [R15][R16] |
| GitHub Issues (this repository's aggregation job) | You want to track findings with an owner per repository | Issues are opened for findings that meet the aggregation job's conditions. It does not include Inspector findings, which are per account and resource. The only machine-readable output is the Issue body, so feeding an analytics platform needs a separate output | Adoption guide ([Detection and prioritization](supply-chain-adoption-guide.md#detection-and-prioritization)) |
| Import the findings of Issues into AWS Security Hub CSPM | You keep the list of findings in one place on the AWS side | You implement and operate the conversion to the AWS Security Finding Format and the sending. Whether findings can be imported the same way into the newer AWS Security Hub (findings in OCSF format) has not been confirmed | Stated in official docs (CSPM accepts findings from a custom product through its API) [R34], not confirmed (importing into the newer Security Hub) |
| OSV and OpenVEX formats | You want to handle vulnerabilities from several ecosystems in one format and tell downstream whether they are affected | The publisher needs an operation to issue them. Whether NetApp issues VEX has not been confirmed | Stated in official docs [R27][R31] |
| SIEM products (Splunk, Datadog and others) | You already collect findings in a SIEM | The primary documents on each product's ingestion method were not read | Not confirmed |

## How to choose

The options are not ranked. Choose what fits your environment in the following order. If two or more apply, use them together.

1. Decide which of the three layers you want to manage.
2. For ONTAP itself, the entry point depends on who updates the version: you (on premises, A) or AWS (FSx for ONTAP, B and C).
3. For the user's code, decide whether to look at it in the repository (GitHub, Renovate, Dependabot) or in resources on AWS (Inspector, Security Hub).
4. For distributed artifacts, decide which of signing, provenance attestations and staged deployment to add, according to the path you want to protect.
5. Decide where findings go (Issues, Security Hub, a SIEM).

Start with three questions.

1. Do you update the ONTAP version yourself, or does AWS apply it? Read A if you do, B and C if AWS does.
2. Can you send AutoSupport to NetApp, and do you hold a support contract? If so, look at Digital Advisor in A1 and Upgrade Advisor in A2. If not, look at the advisory RSS and Upgrade Health Checker.
3. Is the place for findings decided? If it is, read D1.

The options by condition are as follows.

| Condition | Options that suit | Prerequisites and trade-offs | When it does not fit |
|---|---|---|---|
| You can send AutoSupport and hold a support contract | Digital Advisor, Upgrade Advisor (A1, A2) | Requires transmission and support entitlement | Without AutoSupport data, the information Digital Advisor reads is incomplete (inference). Choose the combination in the next row |
| A closed network and a small number of systems | Advisory RSS with a manual match, Upgrade Health Checker (A1, A2) | More manual work | As the number of systems or the update frequency grows, manual matching falls behind and rows older than 90 days since the match date accumulate. If you can meet the condition in the first row, consider that instead |
| You want to continuously watch the dependencies of compute resources on AWS | Amazon Inspector and AWS Security Hub (B2, C2) | Requires enabling and billing. Limited to EC2, ECR, Lambda and similar | If what you want to watch is not a compute resource on AWS, it is outside the scan and produces no findings, which can be misread as "no problem" (for example, on-premises ONTAP itself) |
| You want to manage dependencies and updates per repository | GitHub, Renovate, Dependabot (A3, B2) | Requires the dependency graph. Fixed versions are also held back during the Cooldown | If the code is not on GitHub, the premises of the dependency graph, Dependabot and Renovate do not hold. This is outside this document, and you need another way to read dependencies |
| You want to verify where an artifact came from | Signing, artifact attestations, immutable releases (B3) | The verifying side needs a procedure | If the verifying side has no procedure, signing or attestations are not checked and give no benefit [R24] |
| You want to collect findings in an existing SIEM | EventBridge, Security Hub, Issues (D1) | The SIEM-side integration has not been confirmed | If the SIEM side sets up no ingestion, findings in Issues or Security Hub do not enter the SIEM and the places to look stay split |

## Items that could not be confirmed

The following items have not been confirmed as of the confirmation date (2026-11-17). Finding no statement is not proof that none exists.

| Item | Status | How this document treats it |
|---|---|---|
| Whether Digital Advisor covers FSx for ONTAP | The two Digital Advisor pages on features and limitations and the Cloud Volumes ONTAP integration page do not mention FSx, and the NetApp Console page for FSx for ONTAP does not mention Digital Advisor (2026-11-17) [R38][R39] | Neither coverage nor its absence is stated. C1 treats it as not confirmed |
| Whether the ONTAP version of FSx for ONTAP can be chosen, and an AWS document on how to check it | No dedicated page was found | It does not say that AWS decides the version |
| Whether NetApp provides an SBOM and VEX | Only the vulnerability-handling policy page and the top of the resource list were searched for a statement. None was found | It does not assert either way, and says it has not been confirmed |
| Whether AWS Security Bulletins cover FSx for ONTAP, which FSx for ONTAP settings AWS Config records, and SIEM product integrations | The primary documents were not read | Left in the tables as not confirmed |
| The original text of regulations and guidance | The text of the EU Cyber Resilience Act, CISA's 2026 SBOM minimum elements, and the 2026-07-30 documents from Japan's National Cybersecurity Office and METI could not be retrieved and were not read | Not used as a basis for conformance |

The NetApp security advisory site renders the page body with JavaScript. A plain fetch returns an empty body, so the content rendered in a browser was read.

## References

All confirmation dates are 2026-11-17.

- [R01] NetApp Product Security, Advisories. https://security.netapp.com/advisory/ (checked 2026-11-17)
- [R02] NetApp Product Security, Policy. https://security.netapp.com/policy/ (checked 2026-11-17)
- [R03] NetApp Docs, Digital Advisor. https://docs.netapp.com/us-en/active-iq/task_increase_protection_against_hackers_and_Ransomware_attacks.html (checked 2026-11-17)
- [R04] NetApp Docs, risk display in ONTAP System Manager. https://docs.netapp.com/us-en/ontap/task_admin_monitor_risks.html (checked 2026-11-17)
- [R05] NetApp Docs, when to upgrade ONTAP. https://docs.netapp.com/us-en/ontap/upgrade/when-to-upgrade.html (checked 2026-11-17)
- [R06] NetApp Docs, upgrading ONTAP. https://docs.netapp.com/us-en/ontap/upgrade/index.html (checked 2026-11-17)
- [R07] Amazon FSx for NetApp ONTAP User Guide, maintenance windows. https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/maintenance-windows.html (checked 2026-11-17)
- [R08] Amazon FSx for NetApp ONTAP User Guide, how it works. https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/how-it-works-fsx-ontap.html (checked 2026-11-17)
- [R09] Amazon FSx for NetApp ONTAP User Guide, security. https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/security.html (checked 2026-11-17)
- [R10] AWS Security Bulletins. https://aws.amazon.com/security/security-bulletins/ (checked 2026-11-17)
- [R11] Amazon Inspector User Guide, scanning resources. https://docs.aws.amazon.com/inspector/latest/user/scanning-resources.html (checked 2026-11-17)
- [R12] Amazon Inspector User Guide, SBOM export. https://docs.aws.amazon.com/inspector/latest/user/sbom-export.html (checked 2026-11-17)
- [R13] Amazon Inspector User Guide, vulnerability intelligence and scores. https://docs.aws.amazon.com/inspector/latest/user/findings-understanding-score.html (checked 2026-11-17)
- [R14] Amazon Inspector User Guide, EventBridge integration. https://docs.aws.amazon.com/inspector/latest/user/eventbridge-integration.html (checked 2026-11-17)
- [R15] AWS Security Hub User Guide, SBOM inventory. https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-v2-sbom.html (checked 2026-11-17)
- [R16] AWS Security Hub CSPM User Guide. https://docs.aws.amazon.com/securityhub/latest/userguide/what-is-securityhub.html (checked 2026-11-17)
- [R17] AWS Config Developer Guide. https://docs.aws.amazon.com/config/latest/developerguide/WhatIsConfig.html (checked 2026-11-17)
- [R18] AWS Signer Developer Guide. https://docs.aws.amazon.com/signer/latest/developerguide/Welcome.html (checked 2026-11-17)
- [R19] AWS CodeArtifact User Guide, package origin controls. https://docs.aws.amazon.com/codeartifact/latest/ug/package-origin-controls.html (checked 2026-11-17)
- [R20] AWS SAM Developer Guide, automating updates to serverless applications. https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/automating-updates-to-serverless-apps.html (checked 2026-11-17)
- [R21] GitHub Docs, exporting an SBOM. https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/exporting-a-software-bill-of-materials-for-your-repository (checked 2026-11-17)
- [R22] GitHub Docs, Dependabot options reference. https://docs.github.com/en/code-security/dependabot/working-with-dependabot/dependabot-options-reference (checked 2026-11-17)
- [R23] Renovate Docs, minimumReleaseAge. https://docs.renovatebot.com/configuration-options/#minimumreleaseage (checked 2026-11-17)
- [R24] GitHub Docs, artifact attestations. https://docs.github.com/en/actions/concepts/security/artifact-attestations (checked 2026-11-17)
- [R25] GitHub Docs, immutable releases. https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases (checked 2026-11-17)
- [R26] GitHub Docs, rulesets. https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets (checked 2026-11-17)
- [R27] OpenSSF, OSV schema. https://github.com/ossf/osv-schema (checked 2026-11-17)
- [R28] OpenSSF, case study on GitHub expanding malware advisories. https://openssf.org/blog/2026/10/16/case-study-github-expands-malware-advisories-across-eight-ecosystems-with-openssf/ (checked 2026-11-17)
- [R29] CISA, Known Exploited Vulnerabilities feed. https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json (checked 2026-11-17)
- [R30] FIRST, EPSS. https://www.first.org/epss/ (checked 2026-11-17)
- [R31] OpenVEX specification. https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md (checked 2026-11-17)
- [R32] Amazon Inspector User Guide, configuring the Amazon ECR re-scan duration. https://docs.aws.amazon.com/inspector/latest/user/scanning_resources_configure_duration_setting_ecr.html (checked 2026-11-17)
- [R33] Amazon FSx for NetApp ONTAP User Guide, availability, durability, and deployment options. https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/high-availability-AZ.html (checked 2026-11-17)
- [R34] AWS Security Hub CSPM User Guide, integrating with custom products. https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-custom-providers.html (checked 2026-11-17)
- [R35] NetApp Docs, ONTAP REST API reference, retrieve the cluster (the version field). https://docs.netapp.com/us-en/ontap-restapi/ontap/get-cluster.html (checked 2026-11-17)
- [R36] Amazon FSx API Reference, CreateFileSystemOntapConfiguration and UpdateFileSystemOntapConfiguration. https://docs.aws.amazon.com/fsx/latest/APIReference/API_CreateFileSystemOntapConfiguration.html , https://docs.aws.amazon.com/fsx/latest/APIReference/API_UpdateFileSystemOntapConfiguration.html (checked 2026-11-17)
- [R37] Amazon FSx API Reference, OntapFileSystemConfiguration. https://docs.aws.amazon.com/fsx/latest/APIReference/API_OntapFileSystemConfiguration.html (checked 2026-11-17)
- [R38] NetApp Docs, Digital Advisor features and limitations. https://docs.netapp.com/us-en/active-iq/concept_understand_activeiq_features.html , https://docs.netapp.com/us-en/active-iq/reference_limitations_activeiq.html , https://docs.netapp.com/us-en/storage-management-cloud-volumes-ontap/concept-active-iq.html (checked 2026-11-17)
- [R39] NetApp Docs, Amazon FSx for NetApp ONTAP in the NetApp Console. https://docs.netapp.com/us-en/bluexp-fsx-ontap/start/concept-fsx-aws.html (checked 2026-11-17)

# Cyber Resilience Programme

> **Summary**: This document puts three pillars in one place: software supply chain visibility and response, RTO/RPO with SLA/SLO/SLI, and forensics. It sets the order of work, the role of each pillar in a PDCA cycle, and the accountability view. The current state of each pillar is in the section [Status](#status).

## Purpose

This document holds the overall policy for the three pillars in one place, so that the position and order of each pillar are not mixed up. Procedures for each pillar live in that pillar's published documents. The setup steps for the first pillar are in the adoption guide (`supply-chain-adoption-guide.md`; [en](supply-chain-adoption-guide.md)). The procedures for the second pillar are in the [guide to recovery time and recovery point objectives](recovery-objectives-guide.md), and those for the third pillar are not yet published.

Every guideline cited here is governance guidance. None of it is a legal, compliance, or regulatory judgment. The contractual commitment for a service level is the service owner's own decision, and this project gives no legal or contractual judgment.

Terms used in this document:

- Service owner: the party that provides a service to end users and sets its SLA/SLO/SLI and RTO/RPO (a partner or SI, a system team, an application team)
- Vendor SLA: the SLA that AWS or NetApp publishes for its own service
- Response-time target: the target time for detecting and fixing vulnerabilities. It is not called an SLO until it has been measured in operation
- Policy file: a machine-readable JSON file that holds thresholds, Cooldown values, the response-time target, and similar settings (`docs/agent/supply-chain-policy.json`)
- Cooldown: the minimum time between a new release being published and an update PR being created
- Aggregation job: a scheduled job on the Hub that matches the SBOMs of the target repositories against vulnerability data and opens an Issue for each finding over the threshold
- Hub: the repository that holds the reusable workflows and the Renovate shared preset: [FSx-for-ONTAP-Adoption-Playbook](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook)
- Adoption guide: the document that gathers the setup steps for the first pillar (`supply-chain-adoption-guide.md`)
- Pilot: the period in which the detector's errors are checked on the first two repositories (this repository and the Hub). It is counted from the run in which the aggregation job first produced the findings list for both, and the default is 14 calendar days. When fewer than 20 Issues have been opened, it can be extended by 14 calendar days, up to 2 times (42 calendar days in total). The result decides the reference values and thresholds
- Detection starting point: the time from which the detection target is measured. It is the later of the time a finding first met the condition for opening an Issue and the time the aggregation job first observed that component version. When KEV alone meets the condition, it is recorded as a lower and an upper bound (see ["Response targets" in the adoption guide](supply-chain-adoption-guide.md#response-targets))
- Clean rebuild: building a new environment again from pinned versions and provenance attestations, without trusting the compromised environment
- KEV: the list of vulnerabilities known to be exploited that CISA publishes (Known Exploited Vulnerabilities Catalog)
- EPSS: an estimate of the probability that a vulnerability will be exploited (Exploit Prediction Scoring System)
- SBOM: software bill of materials
- VEX: a format that records, with a basis and in a machine-readable form, whether a vulnerability affects a given version of a component (Vulnerability Exploitability eXchange)
- `MAL-`: the identifier prefix that OpenSSF Malicious Packages gives to malicious packages
- RTO/RPO: recovery time objective and recovery point objective
- DR: disaster recovery
- `[E-nnn]`: the number of a "cannot"-type claim registered in [evidence-ledger.json](../agent/evidence-ledger.json)

Evidence is labeled with four words. `documented` means the relevant part of the source was read. `verified` means it was measured at least once. `hypothesis` means it is this project's interpretation. `open` means it could not be confirmed. The registrations of "cannot"-type claims are in [evidence-ledger.json](../agent/evidence-ledger.json). `open` here is an evidence label, and is separate from the "open" state of an Issue.

## Status

As of 2026-11-17, the state is as follows.

- First pillar: there is an adoption guide and there are verification gates. Of the 22 runs of the Hub aggregation job since 2026-11-13, 17 succeeded, and the latest 5 (2026-11-16 18:15Z to 2026-11-17 09:11Z) all succeeded. The Renovate shared preset is published as a Hub tag. No Spoke has adopted it yet. Details are in [Status in the adoption guide](supply-chain-adoption-guide.md#status). The spec is `cyber-resilience-phase4-supply-chain`, and it is complete
- Second pillar: started (as of 2026-11-20). The [guide to recovery time and recovery point objectives](recovery-objectives-guide.md) and the [measurement results](recovery-measurement-results.md) exist. Measurements are in progress, and only Snapshot restore and clone creation (M1) have results. The restore of FSx backups (M2) is being measured, and the rest are not started
- Third pillar: not started. The spec is planned under the name `cyber-resilience-phase6-forensics`. No public document yet

## Background trends

The two trends below are written only as far as the sources themselves go. Both trends are labeled `hypothesis`: they are this project's reading of the sources, and no source gives a count or a rate of change. The threat types are in [Threat Types Considered in the framework mapping](cyber-resilience-framework-mapping.md#threat-types-considered-as-of-2026-10). No incident, company, or provider is named. The correspondence to NIST CSF 2.0 is in the framework mapping and is not copied here ([NIST CSF 2.0 Function Coverage](cyber-resilience-framework-mapping.md#nist-csf-20-function-coverage)).

| Trend | How the sources put it | Source | Evidence |
|---|---|---|---|
| Attacks aimed at the supply chain and at contractors | IPA's "Top 10 Information Security Threats 2026" (Japanese only) ranks it second for organizations and counts it as an eighth consecutive selection. The ranking comes from deliberation and a vote by a selection panel, not from counts of incidents. The National Police Agency statistics (Japanese only) give 197 to 230 ransomware damage reports a year for 2022 to 2025 (Reiwa 4 to 7) and describe the level as still high. No statistic on supply-chain compromises was found in the parts read | [19], [28] | hypothesis |
| Shorter time from disclosure to exploitation | Project YATA-Shield (Japanese only), issued by several Japanese ministries and agencies, says AI makes finding and fixing vulnerabilities faster, while attacks may also become faster and larger. No source read gives the change over time as a number. As a practitioner discussion, an event report lists the speed-up of AI-driven vulnerability discovery | [20], [17] | hypothesis |

## The three pillars

| Pillar | Purpose | Scope | Setup steps | Status (as of 2026-11-17) |
|---|---|---|---|---|
| 1: Software supply chain visibility and response | Know which components are in use, and respond to vulnerabilities and malicious packages within a target time | SBOMs of the target repositories, Issues from the aggregation job, updates through Renovate, VEX, build provenance, and the ONTAP [upgrade procedure](../ontap-native/ontap-upgrade-for-security-advisories.md). The SBOM minimum elements follow [1] and [2]. Section 6.2 and chapter 7 of [3] guide storage and vulnerability handling | [Adoption guide](supply-chain-adoption-guide.md) | In progress (spec `cyber-resilience-phase4-supply-chain` is complete) |
| 2: RTO/RPO and SLA/SLO/SLI | The service owner sets recovery time and recovery point objectives and measures whether they are met | How to set the objectives, reference architectures (combinations of Snapshot, SnapMirror, AWS Backup, and similar), restore drills | [Guide](recovery-objectives-guide.md), [measurement results](recovery-measurement-results.md) | In progress (as of 2026-11-20; measurements are in progress and only the M1 results are published) |
| 3: Forensics | After a compromise, keep the evidence needed to reconstruct what happened | How to collect evidence, post-incident review | Not yet written | Not started (spec `cyber-resilience-phase6-forensics` not yet written) |

The first pillar refers to these sources:

- Build provenance follows the GitHub artifact attestations procedure [9] and the SLSA Build track [10]
- Malicious packages follow OpenSSF Malicious Packages (OSV format, `MAL-` identifiers) [15]
- AI agent tool definitions follow a research note [11] that recommends an inventory of the MCP servers in use, pinned versions, and detection of definition changes. This research note says itself that it was written with AI assistance and has not been formally reviewed by CSA
- AWS practice on SBOMs, pinned versions, and malicious packages is described in a blog post [14]. It is guidance, not a specification

## Why FSx for ONTAP Appears in a Whole-System Implementation Pattern

This project covers more than storage. It covers how to implement a whole system safely. Putting the data on Amazon FSx for NetApp ONTAP (FSx for ONTAP hereafter) is one pattern for that. Other configurations can build the same separation, for example Amazon EBS with AWS Backup, database replication, or Amazon S3 versioning. Which one fits depends on the workload.

When the data sits on an FSx for ONTAP volume, it becomes a layer separate from the compute (EC2, containers), the software licenses and the database engine. With the layers apart, each layer can in principle do the following. As the "Evidence by claim" table below shows, most of these four points are inference.

- Be inventoried on its own
- Have its version raised on its own
- Have its own recovery points
- Have the compute rebuilt from pinned versions and the same data attached again

### How each pillar uses the separation

| Pillar | What it does with the separation | State |
|---|---|---|
| 1 | The SBOMs, pinned versions and build provenance of the compute-side components are the input to a rebuild. The ONTAP version of the storage layer cannot be chosen through the FSx API and is not returned by it [E-058]. Responding to ONTAP vulnerabilities follows the [upgrade procedure](../ontap-native/ontap-upgrade-for-security-advisories.md), which checks the version on the ONTAP side | The spec is complete. The adoption guide holds the procedure, and no Spoke has adopted it yet |
| 2 | Measures the "clean rebuild". Build the compute from the versions pinned by the first pillar, attach the same volume, and time it from start until the data can be read. Record it separately from the restore time from a recovery point (Snapshot, SnapMirror, AWS Backup). This pillar starts first, so it also defines the hand-over format with the third pillar. The file portal in the S3 Access Points serverless patterns repository already has a [recovery-point list and an approval-gated restore screen](https://github.com/Yoshiki0705/FSx-for-ONTAP-S3AccessPoints-Serverless-Patterns/blob/main/solutions/amplify-portal/docs/data-protection-recovery-design.en.md). What was checked in a real account is recorded separately in the [lab record](https://github.com/Yoshiki0705/FSx-for-ONTAP-S3AccessPoints-Serverless-Patterns/blob/main/infrastructure/shared-backup-vault-lab/docs/verification-record.en.md) | In progress |
| 3 | Preserves evidence on the data side before the compromised compute is rebuilt. The procedure is in [evidence preservation in the Ransomware Recovery Runbook](../runbooks/ransomware-recovery.md). Because the data is a separate layer, the sources of evidence (ONTAP audit logs, FSx API calls in CloudTrail, AWS Backup records) can be counted per access path (inference) | Not started |

### Evidence by claim

The evidence types are the four words defined at the top of this document. For the four Well-Architected items, each page was opened on 2026-11-17 and the quoted statements were checked.

| Claim | Evidence | Content and source |
|---|---|---|
| After the compute is replaced, the data stays on the volume | verified | On ECS on EC2, the marker written before still matched after tasks and instances were replaced. On EKS on Fargate, the objects written before still matched after the Pod was recreated. 2026-11-10, ap-northeast-1, a disposable SVM on an existing Single-AZ file system, a 1 GiB volume, one observation per item. Performance, Multi-AZ, databases and large data sets are out of scope. Sections 3.3 and 5.4 of the [Container-Datastore verification](https://github.com/Yoshiki0705/FSx-for-ONTAP-Container-Datastore-Patterns/blob/main/docs/en/atx-containerization-fsxn-storage-verification.md) |
| A backup can be copied to another Region and restored from the copy | verified | Tokyo to Osaka, 2026-08-28, first-generation SINGLE_AZ_1, 9.4 MiB of data in the volume. The restore took 13 min 21 s (until `CREATED`), once. The relation to data size was not measured. [Hub note](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/domains/data-protection/notes/backup-copies-across-regions-and-accounts.md) (Japanese only) |
| A recovery point in a shared logically air-gapped vault can be restored into an existing file system in another account | verified | 2026-10-12, two accounts in the same Organization, shared through an AWS RAM invitation, ap-northeast-1 and ap-northeast-3, once each. Organization-wide sharing, MPA and a restore from a recovery point in another Region were not tried. [Logically air-gapped vault guide](../data-protection/aws-backup-logically-air-gapped-vault.md) |
| When state moves out of the compute, servers can be replaced without an availability impact | documented | [REL05-BP06](https://docs.aws.amazon.com/wellarchitected/latest/reliability-pillar/rel_mitigate_interaction_failure_stateless.html). The page's examples are session data and do not mention FSx for ONTAP. Applying it to file data is this project's reading (hypothesis) |
| Do not update a running environment in place. Build a new one and switch | documented | [REL08-BP04](https://docs.aws.amazon.com/wellarchitected/latest/reliability-pillar/rel_tracking_change_management_immutable_infrastructure.html). The page does not mention FSx for ONTAP |
| Do not give the backup and restore automation the same access as the production data | documented | [REL09-BP02](https://docs.aws.amazon.com/wellarchitected/latest/reliability-pillar/rel_backing_up_data_secured_backups_data.html). The page lists the same access, and the same security domain for production and backup, as anti-patterns |
| Keep immutable copies outside the original environment | documented | [SEC08-BP03](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_protect_data_rest_automate_protection.html). It appears in the page's desired outcome |
| Compute can be rebuilt from pinned versions, the same volume attached, and service recovered | hypothesis | No end-to-end measurement was found in the 13 repositories, the Hub and Spokes included (searched on 2026-11-17 for `clean rebuild` and the Japanese term for the same, with no match for either). The first measurement of the second pillar checks it |
| Separating the data lets each layer be seen, upgraded and protected on its own | hypothesis | Snapshot, backup, SnapMirror and FlexClone per volume are documented. No record measures how easy each layer is to list or to update. The VMware migration research also writes the separation of OS boot and the data layer as [one hypothesis to be tested](https://github.com/Yoshiki0705/VMware-Migration-EC2-ONTAP/blob/main/docs/ja/research.md) (Japanese only). The software inventory is the job of the first pillar's SBOMs, not something the data's location gives directly |

### Trade-offs

Each row is a constraint on the side that chooses this pattern.

| Item | Content | Source |
|---|---|---|
| Boot disk | The pattern does not use an FSx for ONTAP LUN as a boot disk. The OS disk stays on EBS, and OS patching and licensing stay per instance | [Hub note](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/en/domains/block-storage/notes/when-shared-block-changes-the-design.md) (documented) |
| ONTAP version | The create and update APIs have no version field, and `DescribeFileSystems` does not return one. What the user sets is the start time of the weekly maintenance window [E-058] | [evidence-ledger.json](../agent/evidence-ledger.json) |
| Two management planes | The ONTAP REST and CLI and the FSx API are separate sources of truth for the same resource. A volume created through ONTAP took 12 to 36 minutes to appear in the FSx API in the observations (the results differed between observations and cannot serve as an upper bound). NetApp Console and NetApp System Manager are not supported on second-generation file systems with more than one HA pair [E-023] | [Hub comparison of data protection methods](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/reference/comparison/data-protection-methods.md) (Japanese only), [management planes](../management-planes-cyber-resilience.md), [evidence-ledger.json](../agent/evidence-ledger.json) |
| Cost of the minimum configuration | A file system has lower limits on SSD capacity and throughput capacity, so a monthly charge exists even for small data. In the Hub's estimate, most of the minimum configuration's monthly cost is throughput capacity. The comparison with EBS or S3 changes with the data set size and the number of copies. Check unit prices against the Pricing API on the day | [Hub note](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/en/domains/block-storage/notes/when-ebs-stops-being-the-cheaper-answer.md) |
| How Fargate reaches the data | Fargate tasks and Pods read and write through the object API of S3 Access Points, not through a volume mount. The application has to be changed to use an S3 SDK. EC2-based setups use file mounts (NFS, iSCSI) | Section 1 of the [Container-Datastore verification](https://github.com/Yoshiki0705/FSx-for-ONTAP-Container-Datastore-Patterns/blob/main/docs/en/atx-containerization-fsxn-storage-verification.md) |
| Failure domain | A Snapshot is on the same volume, a SnapMirror destination is on another file system, and a logically air-gapped vault is in an AWS Backup service-owned account. The strength of the separation depends on the layer chosen | The comparison table in the [logically air-gapped vault guide](../data-protection/aws-backup-logically-air-gapped-vault.md) |
| Dependence on ONTAP features | SnapMirror, FlexClone and SnapLock work between ONTAP systems. Where another configuration builds an equivalent separation, that one may fit better | Comparison in the [Hub comparison of data protection methods](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/reference/comparison/data-protection-methods.md) (Japanese only) |
| Consistent recovery points | Data that needs consistency while it is being written, such as a database, needs a consistent recovery point made separately by quiescing or by the database's own feature | Inference (hypothesis) |

### When this fits and when to look at other options

This pattern fits when:

- The data outlives the compute, and you want to rebuild the compute from pinned versions and build provenance
- The same data is used over several paths: NFS, SMB, iSCSI and S3 Access Points
- You already operate ONTAP Snapshot, SnapMirror and FlexClone, or you design recovery points on that assumption

Look at other options when:

- The data is small and the monthly cost of the minimum configuration is out of proportion
- A Fargate or Lambda application has no room to be changed to an S3 SDK
- The main problem is updating the OS disk, not separating the data
- You want to pin the ONTAP version through AWS settings, or to unify management on the AWS API

## Order of work

1. The first pillar. It does not wait for another pillar.
2. The second pillar. It can use the version pinning and build provenance of the first pillar as input for a clean rebuild, but the completion of the first pillar is not a condition for starting.
3. The third pillar. It does not wait for another pillar.

The second and third pillars share a hand-off. The third pillar passes the record of the decision on which recovery point to restore. Whether the time spent choosing the recovery point counts toward RTO is decided by the second pillar. Neither pillar assumes the other is finished, and the pillar that starts first defines the shape of the hand-off.

Each entry in the CISA KEV catalog has a `forensicTriage` field. Entries where it is `Yes` are candidates for input passed to the third pillar. In the catalog fetched on 2026-11-20 (`catalogVersion` 2026.11.18), 108 of 1,786 entries were `Yes` (one fetch). The first `Yes` was added on 2026-06-25, and all 1,627 entries before that date are `No`. All 108 `Yes` entries are due 3 days after they were added. However, 23 `No` entries also have a 3-day due date, so a 3-day due date is not sufficient to infer `Yes`. The meaning follows CISA's directive (BOD 26-04): `Yes` means forensic triage is required and `No` means it is not. Whether `No` means "not needed" or can include "not assessed" is not stated in the documents (an inference from the absence of any retroactive assessment). The `requiredAction` text is the same for `Yes` and `No`, so it cannot tell them apart. The third pillar uses `Yes` as the marker to start the minimum data-side preservation steps (a preservation Snapshot, a copy of the audit logs, up to a FlexClone). It does not read `No` or a missing field as "no preservation needed", and does not use the field as a condition for judging or opening an Issue. The 3-day due date is for patching or mitigation, not for preservation. The directive binds US federal civilian agencies and has no binding force on other operators. The first pillar only shows the value in the Issue body and does not use it to decide whether to open an Issue.

## Service levels

SLA/SLO/SLI and RTO/RPO are values that the service owner sets for end users. They are not the vendor SLA. The definitions of SLA, SLO, and SLI are in the stage 1 section of the Resilience lifecycle framework [13].

The vendor SLA is one input to the service owner's SLO. The SLO also covers what the vendor SLA does not: the application, operations, and recovery procedures. This document gives no vendor SLA figures. When one is needed, quote it from the vendor's published SLA page with the date you read it.

A footnote in the request issued by the Financial Services Agency and the Bank of Japan (Japanese only) uses SLA for a contract on service quality between a financial institution and a vendor, and SLO for an internal target set to meet that SLA [24]. That use of SLA corresponds to vendor SLA in this document. The SLO in the same footnote is close to the service owner's SLO (interpretation).

The distinction between cyber recovery and disaster recovery is not defined here. The plan for the second pillar defines it. Practitioner material that covers this distinction and restore drills includes [26] and [27].

## The PDCA cycle

The three pillars combine as a repeating Plan, Do, Check, Act cycle. The cells for the second and third pillars stay at the level of policy while those pillars have no plan.

| Stage | Pillar 1 | Pillar 2 | Pillar 3 | Links between pillars |
|---|---|---|---|---|
| Plan | The service owner sets the response-time target reference values, the Cooldown (Renovate `minimumReleaseAge` [5]), and the threshold for opening Issues | How to set SLO/RTO/RPO (availability, including data protection and recovery time) | The scope of evidence to keep for forensics | The evidence scope set by pillar 3 is an input to the recovery-point decision in pillar 2 |
| Do | Renovate configuration, reusable workflows, and the aggregation job. Version pinning and build provenance become inputs to a clean rebuild (pillar 2) | Reference architectures (combinations of Snapshot, SnapMirror, AWS Backup, and similar) | Procedures for collecting evidence | Pillar 1's version pinning and build provenance are inputs to pillar 2's rebuild |
| Check | Results against the response-time target (overdue count, detection results) and CI/CD records | SLI measurement and restore-drill results (check points and elapsed time) | Post-incident review (the scope of records) | Pillar 1's run results and the restore-drill results become accountability records (next section) |
| Act | Review of the response-time target and Cooldown | Review of SLOs and architectures | Forensic evidence and recurrence prevention handed to Act | Pillar 3's evidence and recurrence prevention feed pillar 2's recovery-point decision and the review of pillar 1's targets |

The correspondence of the four PDCA stages and the accountability view to NIST CSF 2.0 is in the framework mapping, under [Mapping PDCA and accountability to CSF 2.0](cyber-resilience-framework-mapping.md#mapping-pdca-and-accountability-to-csf-20). The table lives only there and is not copied here. It is an interpretation, not a NIST certification.

## Accountability across the pillars

Accountability is a view that cuts across the three pillars. To meet it, keep three kinds of record:

- Protection settings and log collection in normal operation
- The decisions made when a compromise is detected
- The record up to recovery

Accountability is also used for the A in RACI (the accountable party). Here it carries only the meaning above. The explanation divides into three points: (a) who is responsible (the service owner's organization decides); (b) what the explanation rests on (the integrity and provenance of records); (c) whom to tell (a legal function decides whether notification is required; this project gives no such judgment).

Accountability does not belong to the third pillar alone. It spans the first pillar's records (SBOM, Issues, VEX, run results) and the second pillar's recovery (the record of recovery-point decisions). The number and order of the pillars (1, 2, 3) do not change. Accountability is treated in this section, after the PDCA explanation, as a view separate from the order of the pillars. The event report [17] organizes measures along three axes (defense, recovery, accountability), and this document took that organization as a reference to add accountability as a view that cuts across the pillars.

| Pillar | Records it provides for accountability | How they are used in an explanation |
|---|---|---|
| 1 | Aggregation job run results (opened, updated, and closed Issues, exclusions by VEX with reasons, response-time target results), VEX decisions and approvals (OpenVEX [6]), SBOMs, build provenance | What was included at that point, when it was noticed, and when it was fixed. Why a rebuilt configuration matches the original |
| 2 (policy) | Why a recovery point was chosen and who approved it, restore-test results and elapsed time, RTO/RPO targets and results, the scope of data loss that was accepted | To which point and why the system was restored, and how results compared with the targets |
| 3 (policy) | Evidence per access path and per management plane, timeline reconstruction, records for periods with missing audit data, post-incident review | What happened, where the entry point was, and how to prevent a recurrence |

The rows for pillars 2 and 3 describe policy only. They will be filled in when those pillars have their own plans. For how the records that remain differ by storage type, see the Hub documents listed in the section [Data protection by storage type](#data-protection-by-storage-type).

## Resilience lifecycle stages

The four PDCA stages map to the stages of the Resilience lifecycle framework in AWS Prescriptive Guidance [13]. The framework describes five stages (Set objectives, Design and implement, Evaluate and test, Operate, Respond and learn) as a repeating process. This table carries no best-practice IDs and is not part of the Well-Architected correspondence table.

| PDCA stage | Resilience lifecycle stage |
|---|---|
| Plan | Set objectives |
| Do | Design and implement |
| Check | Evaluate and test, Operate |
| Act | Respond and learn |

Disaster recovery testing spans both Evaluate and test and Operate, so it is not assigned to a single stage.

## Well-Architected best practices

The correspondence between the subjects this project covers and the AWS Well-Architected Framework best-practice IDs is in the framework mapping, under [Best-practice IDs](cyber-resilience-framework-mapping.md#best-practice-ids). The table lives only there. This document lists, one per line, the IDs each pillar implements. The framework version is v13 (2024-11-06) and the reference date is 2026-11-13. The second link for each ID is the same page under the versioned path `2025-02-25`. What `2025-02-25` stands for could not be read from the documentation (`open`) [12].

- Pillar 1: [SEC11-BP02](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/sec_appsec_automate_testing_throughout_lifecycle.html) ([2025-02-25](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/sec_appsec_automate_testing_throughout_lifecycle.html))
- Pillar 1: [SEC11-BP05](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/sec_appsec_centralize_services_for_packages_and_dependencies.html) ([2025-02-25](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/sec_appsec_centralize_services_for_packages_and_dependencies.html))
- Pillar 1: [SEC11-BP06](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/sec_appsec_deploy_software_programmatically.html) ([2025-02-25](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/sec_appsec_deploy_software_programmatically.html))
- Pillar 1: [SEC11-BP07](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/sec_appsec_regularly_assess_security_properties_of_pipelines.html) ([2025-02-25](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/sec_appsec_regularly_assess_security_properties_of_pipelines.html))
- Pillar 2: [REL13-BP01](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/rel_planning_for_recovery_objective_defined_recovery.html) ([2025-02-25](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/rel_planning_for_recovery_objective_defined_recovery.html))
- Pillar 2: [REL13-BP02](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/rel_planning_for_recovery_disaster_recovery.html) ([2025-02-25](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/rel_planning_for_recovery_disaster_recovery.html))
- Pillar 3: [SEC10-BP03](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/sec_incident_response_prepare_forensic.html) ([2025-02-25](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/sec_incident_response_prepare_forensic.html))
- PDCA Check: [OPS09-BP01](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/ops_operations_health_measure_ops_goals_kpis.html) ([2025-02-25](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/ops_operations_health_measure_ops_goals_kpis.html))
- PDCA Check and Act: [OPS09-BP03](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/ops_operations_health_review_ops_metrics_prioritize_improvement.html) ([2025-02-25](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/ops_operations_health_review_ops_metrics_prioritize_improvement.html))
- PDCA Act: [OPS11-BP02](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/ops_evolve_ops_perform_rca_process.html) ([2025-02-25](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/ops_evolve_ops_perform_rca_process.html))

Best practices that the second pillar handles beyond these are added when that pillar's plan sets its scope. All ten pages were read in full on 2026-11-13 and checked against the entries in the framework mapping table.

The correspondence to the NIST SP 800-218 SSDF is in the framework mapping only, under [Correspondence to NIST SSDF](cyber-resilience-framework-mapping.md#correspondence-to-nist-ssdf). The body of the final SSDF Version 1.1 was read on 2026-11-15. Rev. 1 is a draft as of 2026-11-15, and this document does not rely on it.

The Well-Architected correspondence above is not the result of a Well-Architected review and is not an approval by AWS. A service owner can record a review of their own workload in the [AWS Well-Architected Tool](https://aws.amazon.com/well-architected-tool/) [16]. Neither the NIST CSF 2.0 correspondence nor the SSDF correspondence is a NIST certification.

### How to choose among retention-locking options

Ways to protect a recovery point from deletion include both ONTAP features and AWS services, as in REL13-BP02. The table lists them without ranking, with where each suits and its constraints. Choose by where the data lives and by whether the retention must hold even against an administrator's privileges. Several can be layered. A practitioner article suggests setting the lock's retention longer than the time needed to detect and respond [18]. Feature descriptions come from the current official documentation [29], not from that article.

| Option | Suited for | Constraint |
|---|---|---|
| Amazon S3 Object Lock | Keeping S3 objects from being overwritten or deleted for a retention period | Requires versioning. Enabling is irreversible (after it, neither disabling Object Lock nor suspending versioning is an option). Under compliance mode, the retention is not lifted or overwritten until the period ends, even by the root user |
| AWS Backup Vault Lock and logically air-gapped vault | Protecting AWS Backup backups from deletion and isolating them in another vault | In compliance mode, once the grace time (3 days or more) passes, the setting is no longer changed or deleted by anyone. Backups of Amazon FSx for NetApp ONTAP (FSx for ONTAP hereafter) are not copied to a logically air-gapped vault when the file system is encrypted with an AWS managed key [E-009] |
| Amazon EBS Recycle Bin retention rule lock | Recovering from accidental deletion of EBS snapshots, volumes, and EBS-backed AMIs | After unlocking, the rule stays in force until the delay period (7 to 30 days) ends. A locked rule is not modified or deleted in the meantime |
| ONTAP SnapLock (FSx for ONTAP) | Keeping files in a volume under WORM retention | The SnapLock type is chosen when the volume is created. Available on file systems from 2023-07-13 onward |
| ONTAP Tamperproof Snapshot ([configuration](../ontap-native/tamperproof-snapshot.md)) | Locking Snapshots of an existing volume | While locked Snapshots remain, ONTAP cannot be reverted to an earlier version [E-057] |

See also the Hub's [データ保護方式の比較](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/reference/comparison/data-protection-methods.md) (Japanese only).

## Reference values

The values this project publishes (the response-time target, and the reference SLO/RTO/RPO that the second pillar's plan is to publish) are reference values for service owners to replace with their own. They are not a commitment to any end user.

The response-time target is a target and is not called an SLO until it has been measured in operation. The values are in `response_target` of the policy file, and this document shows the same values. The detection target is <!-- policy:response_target.detect_hours -->24 hours (from the detection starting point to the opening of an Issue). The fix target applies from the opening of the Issue to its closing. It is <!-- policy:response_target.fix_days_kev_or_malicious -->7 days for vulnerabilities listed in KEV [7] and for malicious packages, and <!-- policy:response_target.fix_days_high -->14 days for other vulnerabilities rated High or above by CVSS. 14 days is a reference value; the pilot decides, from its results, whether to keep 14 days or extend to 30 days. The EPSS [8] score is attached to an Issue for reference and is not used to classify.

The response-time target applies to findings on the dependencies of the repositories the aggregation job handles. NetApp security advisories for ONTAP are outside it and follow stage 1 of the [ONTAP upgrade procedure](../ontap-native/ontap-upgrade-for-security-advisories.md).

When KEV alone satisfies the trigger, the detection starting point is recorded as a lower and an upper bound, and the monthly check counts a miss of the 24-hour target as certain only when the time measured from the upper bound also exceeds 24 hours. The rules are in [Response targets](supply-chain-adoption-guide.md#response-targets) and [Monthly review steps](supply-chain-adoption-guide.md#monthly-review-steps) of the adoption guide, and are not copied here.

The 24-hour detection target is not a deadline for reporting to an authority. The EU product regulation requires a manufacturer to send an early warning within 24 hours at the latest after becoming aware of an actively exploited vulnerability [4], [25]. That reporting obligation started on 2026-09-11 [4]. The lengths match, but the starting point (becoming aware, versus the publication of an advisory or a KEV entry), the act (a report to an authority, versus opening an Issue), and the recipient all differ. This document does not judge whether the aggregation job or an Issue meets that reporting duty.

### Fix deadlines in public standards

The table summarizes the fix deadlines of published standards as material for a service owner who replaces the reference values with their own. Each standard binds its own audience (companies, government bodies, financial institutions, product manufacturers). None applies to this project or to a service owner, and the table does not say which value is right. Their starting points are not the same as this project's Issue opening.

| Type of standard | Information used to classify | Days to fix | Starting point | Source |
|---|---|---|---|---|
| This project's response-time target | KEV listing, malicious package, CVSS severity | 7 days for KEV-listed and malicious-package findings, 14 days for other findings rated High or above by CVSS (`response_target` in the policy file) | Opening of the Issue | Policy file |
| A security evaluation scheme for companies (the star-3 criteria) | Vulnerabilities the vendor rates critical or high risk, CVSS base score of 7.0 or above, updates without a stated level | 14 days. If that is not possible, risk-reduction measures until the update is applied. The scheme has not started (the page of 2026-10-28 aims at a start around the end of fiscal 2026) | Release of the update | [21] |
| A certification scheme's technical requirements (UK) | Vulnerabilities rated "critical" or "high risk" (CVSS v3 base score of 7 or above, or the vendor's rating) | 14 days | Release | [30] |
| A directive for government agencies (US) | Four variables: whether exposed, KEV listing, whether an attacker can automate, and technical impact (CVSS is not used) | 3 days, 14 days, 60 days, or the next system update | The earlier of the KEV addition and identification on the asset | [31] |
| A standard for government bodies | Application criteria that each body sets in advance, based on product, segment, and severity (CVSS and others) | No number of days | The planned implementation date | [22] |
| A guideline for the financial sector | System criticality, risk, severity | No number of days. It asks for deadlines to be set and results to be managed | Not stated | [23] |
| An EU product regulation | Vulnerabilities with reliable evidence of exploitation (the subject of reporting) | Fixing is "without delay", with no number of days | The manufacturer becoming aware | [25] |

The 14 days in the evaluation scheme start at release, while the response-time target's 14 days start at the opening of the Issue. An Issue is opened after the release, so on the same starting point the response-time target is longer. The procedure for reviewing deadlines is in the adoption guide, in [Using actual results in the PDCA cycle](supply-chain-adoption-guide.md#using-actual-results-in-the-pdca-cycle).

## Data protection by storage type

On-premises storage, Amazon EBS, Amazon S3, Amazon EFS, FSx for ONTAP and the other Amazon FSx services differ in their data protection options and constraints. The differences are an input to the second pillar's choice of recovery points and to the third pillar's scope of evidence. The comparison already exists in the Hub, so this document copies no table or description and only links to it. Documents without an English version link to the Japanese version and are marked Japanese only.

- [ファイルストレージの選択肢の比較](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/reference/comparison/file-storage-options.md) (Japanese only)
- [データ保護方式の比較](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/reference/comparison/data-protection-methods.md) (Japanese only)
- [Can Amazon FSx for NetApp ONTAP Snapshots Alone Ensure Recovery?](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/en/domains/data-protection/notes/snapshots-are-not-a-recovery-plan.md)
- [Amazon FSx for NetApp ONTAP のバックアップコピーだけで復旧できるか？](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/domains/data-protection/notes/backup-copies-across-regions-and-accounts.md) (Japanese only)
- [Amazon FSx for NetApp ONTAP の SnapLock は有効化だけで保護できるか？](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/domains/data-protection/notes/snaplock-and-layered-ransomware-readiness.md) (Japanese only)
- [How Does a Third-Party Backup Product Reach Amazon FSx for NetApp ONTAP?](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/en/domains/data-protection/notes/third-party-backup-reaches-it-by-another-route.md)
- [Is the point where EBS stops being cheaper the instance count?](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/en/domains/block-storage/notes/when-ebs-stops-being-the-cheaper-answer.md)

If the comparison lacks something, do not write it here. Send it to the Hub as a request, or to the plan for the second or third pillar.

## References

Numbers match the `[n]` marks in the text. The references of the adoption guide use a separate numbering, `[Gn]`, which does not mix with the numbers in this table. Dates are in Japan time, and a publication date is the date shown on the page. Titles are given as the issuer wrote them. The reference date is the day the content at that URL was checked. `open` in the evidence column marks a part that could not be confirmed. A Japanese-language source is shown by its original title and marked Japanese only unless an official English translation is linked.

| No. | Title | Issuer | Published / version | URL | Reference date | Evidence |
|---|---|---|---|---|---|---|
| 1 | 2026 Minimum Elements for a Software Bill of Materials (SBOM) | CISA and 17 other agencies (including METI and NCO) | 2026-07-29, version 2.1 | [PDF](https://www.cisa.gov/sites/default/files/2026-07/2026_cisa_sbom_minimum_elements_508c.pdf) | 2026-11-10 | documented |
| 2 | サイバーセキュリティのためのソフトウェア部品表（SBOM）の最小要素に関する国際ガイダンスに共同署名しました (Japanese only) | Ministry of Economy, Trade and Industry (METI) | 2026-07-30 | [meti.go.jp](https://www.meti.go.jp/press/2026/07/20260730001.html) | 2026-11-10 | documented |
| 3 | ソフトウェア管理に向けたSBOM（Software Bill of Materials）の導入に関する手引ver2.0 (Japanese only) | METI | 2024-08-29, ver 2.0 | [meti.go.jp](https://www.meti.go.jp/press/2024/08/20240829001/20240829001.html) | 2026-11-12 | documented (6.2 and chapter 7). Other sections: open |
| 4 | Cyber Resilience Act - Reporting obligations | European Commission | No date shown | [digital-strategy.ec.europa.eu](https://digital-strategy.ec.europa.eu/en/policies/cra-reporting) | 2026-11-14 | documented |
| 5 | Minimum Release Age | Renovate | No date shown | [docs.renovatebot.com](https://docs.renovatebot.com/key-concepts/minimum-release-age/) | 2026-11-10 | documented |
| 6 | OpenVEX Specification v0.2.0 | OpenVEX | v0.2.0 | [GitHub](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md) | 2026-11-10 | documented |
| 7 | Known Exploited Vulnerabilities Catalog | CISA | catalogVersion 2026.11.09 | [cisa.gov](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | 2026-11-10 | verified (fetched once) |
| 8 | GET /epss (FIRST.Org REST API Documentation), EPSS Data (Get the Data), Using EPSS | FIRST (EPSS SIG) | No date shown. The API is marked BETA | [API](https://api.first.org/epss/), [Data](https://www.first.org/epss/data), [Using EPSS](https://www.first.org/epss/using-epss) | 2026-11-12 | documented. The response shape is verified (once) |
| 9 | Using artifact attestations, gh attestation verify | GitHub | No date shown | [docs.github.com](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations), [cli.github.com](https://cli.github.com/manual/gh_attestation_verify) | 2026-11-10 | documented |
| 10 | Build: Track Basics, Build: Requirements for producing artifacts | OpenSSF SLSA | v1.2 | [Track Basics](https://slsa.dev/spec/v1.2/build-track-basics), [Requirements](https://slsa.dev/spec/v1.2/build-requirements) | 2026-11-12 | documented (sections read). Details of isolation strength: open |
| 11 | MCP Security Crisis: Systemic Design Flaws in AI Agent Infrastructure | Cloud Security Alliance (CSAI Foundation) | 2026-05-04 (research note) | [PDF](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/05/CSA_research_note_MCP_security_crisis_20260504-csa-styled.pdf) | 2026-11-10 | documented |
| 12 | AWS Well-Architected Framework (best-practice pages of the Reliability, Operational Excellence, and Security pillars) | AWS | 2024-11-06 (v13) | [welcome.html](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/welcome.html) and the pages listed in the best-practices section | 2026-11-13 | documented. The meaning of the versioned path 2025-02-25: open |
| 13 | Resilience lifecycle framework: A continuous approach to resilience improvement | AWS Prescriptive Guidance | 2023-10-06 (first version) | [docs.aws.amazon.com](https://docs.aws.amazon.com/prescriptive-guidance/latest/resilience-lifecycle-framework/introduction.html) | 2026-11-12 | documented |
| 14 | Well-architected best practices for software supply chain security | AWS Security Blog | The publication date could not be retrieved | [aws.amazon.com](https://aws.amazon.com/blogs/security/well-architected-best-practices-for-software-supply-chain-security/) | 2026-11-10 | documented (as the blog states it). Publication date: open |
| 15 | OpenSSF Malicious Packages | OpenSSF (Securing Critical Projects Working Group) | README as of the reference date | [GitHub](https://github.com/ossf/malicious-packages) | 2026-11-10 | documented |
| 16 | What is AWS Well-Architected? | AWS | 2026-10-01 (Last updated) | [docs.aws.amazon.com](https://docs.aws.amazon.com/wellarchitected/latest/userguide/well-architected.html) | 2026-11-10 | documented |
| 17 | 【開催報告】ランサムウェアに備える「防御」「復旧」「説明責任」— AI エージェント時代に見直す対策と次の一歩 (Japanese only) | AWS (Amazon Web Services blog, Japanese) | Event held 2026-10-26; article published 2026-11-10 | [aws.amazon.com](https://aws.amazon.com/jp/blogs/news/ransomware-security-seminar-oct-2026/) | 2026-11-12 | documented (as what was said at the event) |
| 18 | ランサムウェア被害から医療データの安全を守る (Japanese only) | AWS (Amazon Web Services blog, Japanese) | 2023-11-14 | [aws.amazon.com](https://aws.amazon.com/jp/blogs/news/safeguard-healthcare-data-from-ransomware/) | 2026-11-12 | documented (as what the article states) |
| 19 | 情報セキュリティ10大脅威 2026 (Japanese only) | IPA (Information-technology Promotion Agency, Japan) | Published 2026-01-29; last updated 2026-05-21 | [ipa.go.jp](https://www.ipa.go.jp/security/10threats/10threats2026.html) | 2026-11-12 | documented (the table of organization rankings and the selection method). No official English version was found (open) |
| 20 | AI 性能の高度化を踏まえたサイバーセキュリティ対策の強化について～Project YATA-Shield～ (Japanese only) | Cabinet Secretariat National Cybersecurity Office and other ministries and agencies | 2026-05-18 | [PDF](https://www.cyber.go.jp/pdf/press/20260518_AI_CS_Package.pdf) | 2026-11-12 | documented |
| 21 | ★3・★4要求事項・評価基準（Ver.1.1:2026年10月28日） (Japanese only) | METI | Ver 1.1, 2026-10-28 | [xlsx](https://www.meti.go.jp/policy/netsecurity/docs/scs/SCS-400-criteria-v1.1.xlsx) | 2026-11-12 | documented |
| 22 | 政府機関等の対策基準策定のためのガイドライン（令和７年度版） 第３部～付録 (Japanese only) | National Cybersecurity Office | Reiwa 7 edition; reflects the partial revision of 2026-06-12 | [PDF](https://www.cyber.go.jp/pdf/policy/general/guider8_6_02.pdf) | 2026-11-12 | documented (7.2.1) |
| 23 | 金融分野におけるサイバーセキュリティに関するガイドライン (Guidelines on Cybersecurity for the Financial Sector) | Financial Services Agency | 2024-10-04 | [PDF](https://www.fsa.go.jp/news/r6/sonota/20241004/18.pdf), [provisional English translation](https://www.fsa.go.jp/common/law/cybersecurity_guideline_en.pdf) | 2026-11-12 | documented (2.2.3, and the second sub-item of 2.2.1) |
| 24 | 「フロンティア AI による脅威変化を踏まえた金融機関等の短期的な対応」に係る要請について (Japanese only) | Financial Services Agency, Bank of Japan | 2026-05-22 | [PDF](https://www.fsa.go.jp/news/r7/sonota/20260522-5/01.pdf) | 2026-11-12 | documented (footnote 4) |
| 25 | Regulation (EU) 2024/2847 (Cyber Resilience Act) | European Parliament, Council of the European Union | OJ L, 2024/2847, 20.11.2024 | [EUR-Lex](https://eur-lex.europa.eu/eli/reg/2024/2847/oj) | 2026-11-12 | documented (Article 14, 71, Annex I Part II) |
| 26 | Cyber recovery on AWS: A reference approach for recovering from ransomware and destructive events | AWS Architecture Blog | Published 2026-05-20; updated 2026-10-22 | [aws.amazon.com](https://aws.amazon.com/blogs/architecture/cyber-resilience-on-aws-a-reference-approach-for-recovery-from-ransomware-and-destructive-events/) | 2026-11-12 | documented |
| 27 | Planning a NIST-aligned ransomware recovery strategy on AWS, Building isolated, immutable backups for ransomware recovery on AWS, Test backups and restore critical workloads after ransomware on AWS | AWS (AWS re:Post; a three-part series by AWS Support) | 2026-10-15 | [Part 1](https://repost.aws/articles/ARatcO81HOTyCDYQbX5h30pg/planning-a-nist-aligned-ransomware-recovery-strategy-on-aws), [Part 2](https://repost.aws/articles/AR9O5kMiZdRL2CBrdXqUI38g/building-isolated-immutable-backups-for-ransomware-recovery-on-aws), [Part 3](https://repost.aws/articles/ARU6N19cQrQi66Oj-RiasMPQ/test-backups-and-restore-critical-workloads-after-ransomware-on-aws) | 2026-11-12 | documented |
| 28 | 令和７年におけるサイバー空間をめぐる脅威の情勢等について (Japanese only) | National Police Agency | March 2026 (Reiwa 8) | [PDF](https://www.npa.go.jp/publications/statistics/cybersecurity/data/R7/R07_cyber_jousei.pdf) | 2026-11-12 | documented (the graph of ransomware damage reports) |
| 29 | Configuring S3 Object Lock, Locking objects with Object Lock, AWS Backup Vault Lock, Recover deleted EBS volumes, EBS snapshots, and EBS-backed AMIs with Recycle Bin, How SnapLock works | AWS | No date shown | [S3 configuration](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock-configure.html), [S3 overview](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html), [Backup Vault Lock](https://docs.aws.amazon.com/aws-backup/latest/devguide/vault-lock.html), [EBS Recycle Bin](https://docs.aws.amazon.com/ebs/latest/userguide/recycle-bin.html), [SnapLock](https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/snaplock.html) | 2026-11-12 | documented |
| 30 | Cyber Essentials: Requirements for IT Infrastructure v3.3 | NCSC (UK National Cyber Security Centre) | v3.3, April 2026 | [ncsc.gov.uk](https://www.ncsc.gov.uk/files/cyber-essentials-requirements-for-it-infrastructure-v3-3.pdf) | 2026-11-13 | documented (section Security Update Management) |
| 31 | BOD 26-04: Prioritizing Security Updates Based on Risk | CISA | 2026-06-10 | [cisa.gov](https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk) | 2026-11-13 | documented (Table 1 is an image, read as an image on 2026-11-12) |

[3] is cited only for 6.2 (storing SBOMs) and chapter 7 (vulnerability-handling procedure). [17] and [18] are sources for practitioner discussion and are not sources for specifications or guidance.

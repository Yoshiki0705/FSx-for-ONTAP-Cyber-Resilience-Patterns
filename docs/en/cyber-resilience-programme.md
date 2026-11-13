# Cyber Resilience Programme

> **Summary**: This document puts three pillars in one place: software supply chain visibility and response, RTO/RPO with SLA/SLO/SLI, and forensics. It sets the order of work, the role of each pillar in a PDCA cycle, and the accountability view. The first pillar is under way. The second and third pillars have no spec yet.

## Purpose

This document holds the overall policy for the three pillars in one place, so that the position and order of each pillar's spec are not mixed up. Procedures for each pillar live in that pillar's spec and documents. The setup steps for the first pillar are in the Adoption_Guide (`supply-chain-adoption-guide.md`; [en](supply-chain-adoption-guide.md)).

Every guideline cited here is governance guidance. None of it is a legal, compliance, or regulatory judgment. The contractual commitment for a service level is the Service_Owner's own decision, and this project gives no legal or contractual judgment.

Terms used in this document:

- Service_Owner: the party that provides a service to end users and sets its SLA/SLO/SLI and RTO/RPO (a partner or SI, a system team, an application team)
- Vendor_SLA: the SLA that AWS or NetApp publishes for its own service
- Response_Target: the target time for detecting and fixing vulnerabilities. It is not called an SLO until it has been measured in operation
- Policy_File: a machine-readable JSON file that holds thresholds, Cooldown values, the Response_Target, and similar settings (`docs/agent/supply-chain-policy.json`)
- Cooldown: the minimum time between a new release being published and an update PR being created
- Aggregator: a scheduled job that matches the SBOMs of the target repositories against vulnerability data and opens an Issue for each finding over the threshold

Evidence is labeled with four words. `documented` means the relevant part of the source was read. `verified` means it was measured at least once. `hypothesis` means it is this project's interpretation. `open` means it could not be confirmed.

## Trends behind this programme

The two trends below are written only as far as the sources themselves go. The wording has not yet been compared with [Threat Types Considered in the framework mapping](cyber-resilience-framework-mapping.md#threat-types-considered-as-of-2026-10), so both are labeled `hypothesis`. No incident, company, or provider is named. The correspondence to NIST CSF 2.0 is in the framework mapping and is not copied here ([NIST CSF 2.0 Function Coverage](cyber-resilience-framework-mapping.md#nist-csf-20-function-coverage)).

| Trend | How the sources put it | Source | Evidence |
|---|---|---|---|
| Attacks aimed at the supply chain and at contractors | IPA's "Top 10 Information Security Threats 2026" (Japanese only) ranks it second for organizations and counts it as an eighth consecutive selection. The ranking comes from deliberation and a vote by a selection panel, not from counts of incidents. The National Police Agency statistics (Japanese only) give 197 to 230 ransomware damage reports a year for 2022 to 2025 (Reiwa 4 to 7) and describe the level as still high. No statistic on supply-chain compromises was found in the parts read | [19], [28] | hypothesis |
| Shorter time from disclosure to exploitation | Project YATA-Shield (Japanese only), issued by several Japanese ministries and agencies, says AI makes finding and fixing vulnerabilities faster, while attacks may also become faster and larger. No source read gives the change over time as a number. As a practitioner discussion, an event report lists the speed-up of AI-driven vulnerability discovery | [20], [17] | hypothesis |

## The three pillars

| Pillar | Purpose | Scope | Spec | Status |
|---|---|---|---|---|
| 1: Software supply chain visibility and response | Know which components are in use, and respond to vulnerabilities and malicious packages within a target time | SBOMs of the target repositories, Issues from the Aggregator, updates through Renovate, VEX, build provenance, and the ONTAP [upgrade procedure](../ontap-native/ontap-upgrade-for-security-advisories.md). The SBOM minimum elements follow [1] and [2]. Section 6.2 and chapter 7 of [3] guide storage and vulnerability handling | `cyber-resilience-phase4-supply-chain` | In progress |
| 2: RTO/RPO and SLA/SLO/SLI | The Service_Owner sets recovery time and recovery point objectives and measures whether they are met | How to set the objectives, reference architectures (combinations of Snapshot, SnapMirror, AWS Backup, and similar), restore drills | Not yet written | Not started |
| 3: Forensics | After a compromise, keep the evidence needed to reconstruct what happened | How to collect evidence, post-incident review | Not yet written | Not started |

The first pillar refers to these sources:

- Build provenance follows the GitHub artifact attestations procedure [9] and the SLSA Build track [10]
- Malicious packages follow OpenSSF Malicious Packages (OSV format, `MAL-` identifiers) [15]
- AI agent tool definitions follow a research note [11] that recommends an inventory of the MCP servers in use, pinned versions, and detection of definition changes. The note says itself that it was written with AI assistance and has not been formally reviewed by CSA
- AWS practice on SBOMs, pinned versions, and malicious packages is described in a blog post [14]. It is guidance, not a specification

## Order of work

1. The first pillar. It does not wait for another pillar.
2. The second pillar. It can use the version pinning and build provenance of the first pillar as input for a clean rebuild, but the completion of the first pillar is not a condition for starting.
3. The third pillar. It does not wait for another pillar.

The second and third pillars share a hand-off. The third pillar passes the record of the decision on which recovery point to restore. Whether the time spent choosing the recovery point counts toward RTO is decided by the second pillar. Neither pillar assumes the other is finished, and the pillar that starts first defines the shape of the hand-off.

## Service levels

SLA/SLO/SLI and RTO/RPO are values that the Service_Owner sets for end users. They are not the Vendor_SLA. Definitions are in stage 1 of the Resilience lifecycle framework [13].

The Vendor_SLA is one input to the Service_Owner's SLO. The SLO also covers what the Vendor_SLA does not: the application, operations, and recovery procedures. This document gives no Vendor_SLA figures. When one is needed, quote it from the vendor's published SLA page with the date you read it.

A footnote in the request issued by the Financial Services Agency and the Bank of Japan (Japanese only) uses SLA for a contract on service quality between a financial institution and a vendor, and SLO for an internal target set to meet that SLA [24]. That use of SLA corresponds to Vendor_SLA in this document. The SLO in the same footnote is close to the Service_Owner's SLO (interpretation).

The distinction between cyber recovery and disaster recovery is not defined here. The second pillar's spec defines it. Practitioner material that covers this distinction and restore drills includes [26] and [27].

## The PDCA cycle

The three pillars combine as a repeating Plan, Do, Check, Act cycle. The cells for the second and third pillars stay at the level of policy while those specs do not exist.

| Stage | Pillar 1 | Pillar 2 | Pillar 3 | Links between pillars |
|---|---|---|---|---|
| Plan | The Service_Owner sets the Response_Target reference values, the Cooldown (Renovate `minimumReleaseAge` [5]), and the threshold for opening Issues | How to set SLO/RTO/RPO (availability, including data protection and recovery time) | The scope of evidence to keep for forensics | The evidence scope set by pillar 3 is an input to the recovery-point decision in pillar 2 |
| Do | Renovate configuration, reusable workflows, and the Aggregator. Version pinning and build provenance become inputs to a clean rebuild (pillar 2) | Reference architectures (combinations of Snapshot, SnapMirror, AWS Backup, and similar) | Procedures for collecting evidence | Pillar 1's version pinning and build provenance are inputs to pillar 2's rebuild |
| Check | Results against the Response_Target (overdue count, detection results) and CI/CD records | SLI measurement and restore-drill results (check points and elapsed time) | Post-incident review (the scope of records) | Pillar 1's run results and the restore-drill results become accountability records (next section) |
| Act | Review of the Response_Target and Cooldown | Review of SLOs and architectures | Forensic evidence and recurrence prevention handed to Act | Pillar 3's evidence and recurrence prevention feed pillar 2's recovery-point decision and the review of pillar 1's targets |

The correspondence of the four PDCA stages and the accountability view to NIST CSF 2.0 is in the framework mapping, under [Mapping PDCA and accountability to CSF 2.0](cyber-resilience-framework-mapping.md#mapping-pdca-and-accountability-to-csf-20). The table lives only there and is not copied here. It is an interpretation, not a NIST certification.

## Accountability across the pillars

Accountability is a view that cuts across the three pillars. It means being able to keep and explain three things:

- Protection settings and log collection in normal operation
- The decisions made when a compromise is detected
- The record up to recovery

Accountability is also used for the A in RACI (the accountable party). Here it carries only the meaning above. The explanation is split into (1) who is responsible (the Service_Owner's organization decides), (2) what the explanation rests on (the integrity and provenance of records), and (3) whom to tell (a legal function decides whether notification is required; this project gives no such judgment).

Accountability does not belong to the third pillar alone. It spans the first pillar's records (SBOM, Issues, VEX, run results) and the second pillar's recovery (the record of recovery-point decisions). The number and order of the pillars (1, 2, 3) do not change. Accountability starts from records in normal operation, so it sits before recovery. This order follows the event report [17] that describes three axes (defense, recovery, accountability) and the links between them.

| Pillar | Records it provides for accountability | How they are used in an explanation |
|---|---|---|
| 1 | Aggregator run results (opened, updated, and closed Issues, exclusions by VEX with reasons, Response_Target results), VEX decisions and approvals (OpenVEX [6]), SBOMs, build provenance | What was included at that point, when it was noticed, and when it was fixed. Why a rebuilt configuration matches the original |
| 2 (policy) | Why a recovery point was chosen and who approved it, restore-test results and elapsed time, RTO/RPO targets and results, the scope of data loss that was accepted | To which point and why the system was restored, and how results compared with the targets |
| 3 (policy) | Evidence per access path and per management plane, timeline reconstruction, records for periods with missing audit data, post-incident review | What happened, where the entry point was, and how to prevent a recurrence |

The weakness of this section is that readers have to map two cuts (pillars and accountability) onto each other. Revisit the rows for pillars 2 and 3 when their specs exist. For how records differ by storage type, see the Hub documents in [Data protection by storage type](#data-protection-by-storage-type).

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

The correspondence between this project's components and the AWS Well-Architected Framework best-practice IDs is in the framework mapping, under [Best-practice IDs](cyber-resilience-framework-mapping.md#best-practice-ids). The table lives only there. This document lists, one per line, the IDs each pillar implements. The framework version is v13 (2024-11-06) and the reference date is 2026-11-13. The second link for each ID is the same page under the versioned path `2025-02-25`. What `2025-02-25` stands for could not be read from the documentation (`open`) [12].

- Pillar 1: [SEC11-BP02](https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_appsec_automate_testing_throughout_lifecycle.html) ([2025-02-25](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/sec_appsec_automate_testing_throughout_lifecycle.html))
- Pillar 1: [SEC11-BP05](https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_appsec_centralize_services_for_packages_and_dependencies.html) ([2025-02-25](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/sec_appsec_centralize_services_for_packages_and_dependencies.html))
- Pillar 1: [SEC11-BP06](https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_appsec_deploy_software_programmatically.html) ([2025-02-25](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/sec_appsec_deploy_software_programmatically.html))
- Pillar 1: [SEC11-BP07](https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_appsec_regularly_assess_security_properties_of_pipelines.html) ([2025-02-25](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/sec_appsec_regularly_assess_security_properties_of_pipelines.html))
- Pillar 2: [REL13-BP01](https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_planning_for_recovery_objective_defined_recovery.html) ([2025-02-25](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/rel_planning_for_recovery_objective_defined_recovery.html))
- Pillar 2: [REL13-BP02](https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_planning_for_recovery_disaster_recovery.html) ([2025-02-25](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/rel_planning_for_recovery_disaster_recovery.html))
- Pillar 3: [SEC10-BP03](https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_incident_response_prepare_forensic.html) ([2025-02-25](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/sec_incident_response_prepare_forensic.html))
- PDCA Check: [OPS09-BP01](https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_operations_health_measure_ops_goals_kpis.html) ([2025-02-25](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/ops_operations_health_measure_ops_goals_kpis.html))
- PDCA Check and Act: [OPS09-BP03](https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_operations_health_review_ops_metrics_prioritize_improvement.html) ([2025-02-25](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/ops_operations_health_review_ops_metrics_prioritize_improvement.html))
- PDCA Act: [OPS11-BP02](https://docs.aws.amazon.com/wellarchitected/latest/framework/ops_evolve_ops_perform_rca_process.html) ([2025-02-25](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/ops_evolve_ops_perform_rca_process.html))

Best practices that the second pillar handles beyond these are added when that pillar's spec sets its scope. All ten pages were read in full on 2026-11-13 and checked against the entries in the framework mapping table.

This correspondence is not the result of a Well-Architected review and is not an approval by AWS. A Service_Owner can record a review of their own workload in the [AWS Well-Architected Tool](https://aws.amazon.com/well-architected-tool/) [16]. The correspondence to NIST CSF 2.0 is not a NIST certification either.

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

The values this project publishes (the Response_Target, and the reference SLO/RTO/RPO that later specs publish) are reference values for users to replace with their own. They are not a commitment to any end user.

The Response_Target is a target and is not called an SLO until it has been measured in operation. The values are in `response_target` of the Policy_File, and this document shows the same values. The detection target is <!-- policy:response_target.detect_hours -->24 hours (from the starting point to the opening of an Issue). The fix target is <!-- policy:response_target.fix_days_kev_or_malicious -->7 days for vulnerabilities listed in KEV [7] and for malicious packages, and <!-- policy:response_target.fix_days_high -->14 days for other vulnerabilities rated High or above by CVSS (measured from opening the Issue to closing it; 14 days is a reference value, and the pilot decides whether to keep it or return to 30 days). The EPSS [8] score is attached to an Issue for reference and is not used to classify.

The 24-hour detection target is not a deadline for reporting to an authority. The EU product regulation requires a manufacturer to send an early warning within 24 hours at the latest after becoming aware of an actively exploited vulnerability [4], [25]. The lengths match, but the starting point (becoming aware, versus the publication of an advisory or a KEV entry), the act (a report to an authority, versus opening an Issue), and the recipient all differ. This document does not judge whether the Aggregator or an Issue meets that reporting duty.

### Fix deadlines in public standards

The table summarizes the fix deadlines of published standards as material for a Service_Owner who replaces the reference values with their own. Each standard binds its own audience (companies, government bodies, financial institutions, product manufacturers). None applies to this project or to a Service_Owner, and the table does not say which value is right. Their starting points are not the same as this project's Issue opening.

| Type of standard | Information used to classify | Days to fix | Starting point | Source |
|---|---|---|---|---|
| This project's Response_Target | KEV listing, malicious package, CVSS severity | As in the paragraph above | Opening of the Issue | Policy_File |
| A security evaluation scheme for companies (the star-3 criteria) | Vulnerabilities the vendor rates critical or high risk, CVSS base score of 7.0 or above, updates without a stated level | 14 days. If that is not possible, risk-reduction measures until the update is applied. The scheme has not started (the page of 2026-10-28 aims at a start around the end of fiscal 2026) | Release of the update | [21] |
| A certification scheme's technical requirements (UK) | Vulnerabilities rated "critical" or "high risk" (CVSS v3 base score of 7 or above, or the vendor's rating) | 14 days | Release | [30] |
| A directive for government agencies (US) | Four variables: whether exposed, KEV listing, whether an attacker can automate, and technical impact (CVSS is not used) | 3 days, 14 days, 60 days, or the next system update | The earlier of the KEV addition and identification on the asset | [31] |
| A standard for government bodies | Application criteria that each body sets in advance, based on product, segment, and severity (CVSS and others) | No number of days | The planned implementation date | [22] |
| A guideline for the financial sector | System criticality, risk, severity | No number of days. It asks for deadlines to be set and results to be managed | Not stated | [23] |
| An EU product regulation | Vulnerabilities with reliable evidence of exploitation (the subject of reporting) | Fixing is "without delay", with no number of days | The manufacturer becoming aware | [25] |

The 14 days in the evaluation scheme start at release, while the Response_Target's 14 days start at the opening of the Issue. An Issue is opened after the release, so on the same starting point the Response_Target is longer. The procedure for reviewing deadlines is in the Adoption_Guide, in [Using actual results in the PDCA cycle](supply-chain-adoption-guide.md#using-actual-results-in-the-pdca-cycle).

## Data protection by storage type

On-premises storage, Amazon EBS, Amazon S3, Amazon EFS, FSx for ONTAP and the other Amazon FSx services differ in their data protection options and constraints. The differences are an input to the second pillar's choice of recovery points and to the third pillar's scope of evidence. The comparison already exists in the Hub, so this document copies no table or description and only links to it. Documents without an English version link to the Japanese version and are marked Japanese only.

- [ファイルストレージの選択肢の比較](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/reference/comparison/file-storage-options.md) (Japanese only)
- [データ保護方式の比較](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/reference/comparison/data-protection-methods.md) (Japanese only)
- [Can Amazon FSx for NetApp ONTAP Snapshots Alone Ensure Recovery?](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/en/domains/data-protection/notes/snapshots-are-not-a-recovery-plan.md)
- [Amazon FSx for NetApp ONTAP のバックアップコピーだけで復旧できるか？](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/domains/data-protection/notes/backup-copies-across-regions-and-accounts.md) (Japanese only)
- [Amazon FSx for NetApp ONTAP の SnapLock は有効化だけで保護できるか？](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/domains/data-protection/notes/snaplock-and-layered-ransomware-readiness.md) (Japanese only)
- [How Does a Third-Party Backup Product Reach Amazon FSx for NetApp ONTAP?](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/en/domains/data-protection/notes/third-party-backup-reaches-it-by-another-route.md)
- [Is the point where EBS stops being cheaper the instance count?](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/en/domains/block-storage/notes/when-ebs-stops-being-the-cheaper-answer.md)

If the comparison lacks something, do not write it here. Send it to the Hub as a request, or to the spec of the second or third pillar.

## References

Numbers match the `[n]` marks in the text. Titles are given as the issuer wrote them. The reference date is the day the content at that URL was checked. `open` in the evidence column marks a part that could not be confirmed. A Japanese-language source is shown by its original title and marked Japanese only unless an official English translation is linked.

| No. | Title | Issuer | Published / version | URL | Reference date | Evidence |
|---|---|---|---|---|---|---|
| 1 | 2026 Minimum Elements for a Software Bill of Materials (SBOM) | CISA and 17 other agencies (including METI and NCO) | 2026-07-29, version 2.1 | [PDF](https://www.cisa.gov/sites/default/files/2026-07/2026_cisa_sbom_minimum_elements_508c.pdf) | 2026-11-10 | documented |
| 2 | サイバーセキュリティのためのソフトウェア部品表（SBOM）の最小要素に関する国際ガイダンスに共同署名しました (Japanese only) | Ministry of Economy, Trade and Industry (METI) | 2026-07-30 | [meti.go.jp](https://www.meti.go.jp/press/2026/07/20260730001.html) | 2026-11-10 | documented |
| 3 | ソフトウェア管理に向けたSBOM（Software Bill of Materials）の導入に関する手引ver2.0 (Japanese only) | METI | 2024-08-29, ver 2.0 | [meti.go.jp](https://www.meti.go.jp/press/2024/08/20240829001/20240829001.html) | 2026-11-12 | documented (6.2 and chapter 7). Other sections: open |
| 4 | Cyber Resilience Act - Reporting obligations | European Commission | No date shown | [digital-strategy.ec.europa.eu](https://digital-strategy.ec.europa.eu/en/policies/cra-reporting) | 2026-11-12 | documented |
| 5 | Minimum Release Age | Renovate | No date shown | [docs.renovatebot.com](https://docs.renovatebot.com/key-concepts/minimum-release-age/) | 2026-11-10 | documented |
| 6 | OpenVEX Specification v0.2.0 | OpenVEX | v0.2.0 | [GitHub](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md) | 2026-11-10 | documented |
| 7 | Known Exploited Vulnerabilities Catalog | CISA | catalogVersion 2026.11.09 | [cisa.gov](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | 2026-11-10 | verified (fetched once) |
| 8 | GET /epss (FIRST.Org REST API Documentation), EPSS Data (Get the Data), Using EPSS | FIRST (EPSS SIG) | No date shown. The API is marked BETA | [API](https://api.first.org/epss/), [Data](https://www.first.org/epss/data), [Using EPSS](https://www.first.org/epss/using-epss) | 2026-11-12 | documented. The response shape is verified (once) |
| 9 | Using artifact attestations, gh attestation verify | GitHub | No date shown | [docs.github.com](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations), [cli.github.com](https://cli.github.com/manual/gh_attestation_verify) | 2026-11-10 | documented |
| 10 | Build: Track Basics, Build: Requirements for producing artifacts | OpenSSF SLSA | v1.2 | [Track Basics](https://slsa.dev/spec/v1.2/build-track-basics), [Requirements](https://slsa.dev/spec/v1.2/build-requirements) | 2026-11-12 | documented (sections read). Details of isolation strength: open |
| 11 | MCP Security Crisis: Systemic Design Flaws in AI Agent Infrastructure | Cloud Security Alliance (CSAI Foundation) | 2026-05-04 (research note) | [PDF](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/05/CSA_research_note_MCP_security_crisis_20260504-csa-styled.pdf) | 2026-11-10 | documented |
| 12 | AWS Well-Architected Framework (best-practice pages of the Reliability, Operational Excellence, and Security pillars) | AWS | 2024-11-06 (v13) | [welcome.html](https://docs.aws.amazon.com/wellarchitected/latest/framework/welcome.html) and the pages listed in the best-practices section | 2026-11-13 | documented. The meaning of the versioned path 2025-02-25: open |
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

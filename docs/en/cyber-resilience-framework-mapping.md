# Cyber Resilience Framework Mapping

> **Executive summary**: This project mainly covers NIST CSF 2.0 Protect (WORM, snapshot locking, inline scanning) and Respond (approval-based quarantine), contributes to parts of Detect and Identify, and leaves Govern to the organisation. Three main constraints apply: behavioural ML is delegated to a SIEM; SMB name-mapping blocks do not take effect on NTFS volumes [E-002]; and ARP's documented detection conditions are write-side, with no documented condition that fires on reads alone (inference) [E-012] (see the exfiltration scenario and the [exfiltration runbook](../runbooks/data-exfiltration-response.md)).

This repository is designed against [NIST Cybersecurity Framework (CSF) 2.0](https://www.nist.gov/cyberframework), with additional alignment to [NIST SP 800-61r3](https://csrc.nist.gov/pubs/sp/800/61/r3/final) (Incident Handling) and [NIST IR 8374r1](https://csrc.nist.gov/pubs/ir/8374/r1/final) (Ransomware Risk Management).

## Threat Types Considered (as of 2026-10)

Incidents in which personal data is taken from public web systems continue to be disclosed across industries and organisation sizes. They are not limited to e-commerce sites and extend to membership services, booking, line-of-business systems and customer support. Entry points fall into known vulnerabilities in shared software, weak authentication on admin consoles or stolen credentials, and design and access-control flaws in individual applications and APIs. Bulk retrieval through legitimate functions looks like normal responses, so monitoring that only watches for rising error rates can miss it. Alongside leaks, malicious programs may be planted, unauthorised accounts created, and data altered or deleted. When the cause is not disclosed, whether an investigation can look back depends on whether logs were preserved. When a cloud platform's management plane or virtualisation layer is compromised, snapshots and backups inside the same management boundary can be lost as well. This document organises these into the eight threat types below and maps them to CSF 2.0 categories and to the sections of this document.

| Type | Description | Main CSF 2.0 categories | Section |
|---|---|---|---|
| A | Exploitation of known vulnerabilities in shared software such as frameworks, CMSs and plug-ins | ID.RA, PR.PS, DE.CM | Storage-Layer Scope and Boundary (not a storage-layer control) |
| B | Weak authentication on admin consoles, stolen credentials | PR.AA, DE.CM, GV.RR | Management-Plane Compromise (MAV and tamperproof snapshots against ONTAP admin compromise) |
| C | Design and access-control flaws in individual applications and APIs (excessive data in responses, features usable anonymously, keys embedded in distributed apps) | PR.AA, PR.DS, PR.PS | Storage-Layer Scope and Boundary; Exfiltration (S3 Access Points policy and file system user when used as a file store) |
| D | Bulk retrieval through legitimate functions; it looks like normal responses, so monitoring that only watches error rates can miss it | DE.CM, DE.AE, RS.AN | Exfiltration |
| E | Tampering, planting malicious programs, deleting data | PR.DS, DE.CM, RC.RP | Encryption and destruction |
| F | Compromise of a cloud platform's management plane or virtualisation layer; snapshots and backups in the same boundary can be lost too | PR.DS, PR.IR, RC.RP, GV.RM | Management-Plane Compromise |
| G | Cause cannot be determined (insufficient logs); whether logs were preserved decides the first response | DE.AE, RS.AN, PR.PS | Both scenarios |
| H | Chains of dependency on contractors and cloud platforms | GV.SC | Organisational decision (governance guidance, not legal judgement) |

As neutral references, the threats for organisations in IPA's "[Information Security 10 Major Threats 2026](https://www.ipa.go.jp/security/10threats/10threats2026.html)" (Japanese) that overlap with this list are, by name only: ransomware damage, attacks targeting the supply chain and contractors, attacks exploiting system vulnerabilities, and information leaks through insider misconduct. MITRE ATT&CK technique IDs are in the "MITRE ATT&CK Mapping" section.

This section reflects the picture as of 2026-10 and is reviewed quarterly (January, April, July, October). The next review is 2027-01.

## NIST CSF 2.0 Function Coverage

| CSF 2.0 Function | Main categories | Status | This Repo | Companion Repo ([observability](https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations)) | Gap / Organizational Responsibility |
|-------------------|-----------------|:------:|-----------|---------------------|-----|
| **Govern (GV)** | GV.RM, GV.RR, GV.OC | ⚠️ | CloudFormation-as-code audit trail, cfn-guard compliance rules, `solutions/compliance/` evidence collection. Pre-migration data protection planning and cost modeling ([vault guide](../data-protection/aws-backup-logically-air-gapped-vault.md)). Approval of destructive operations (ONTAP MAV, AWS Backup MPA) | CloudWatch Logs + SNS notification trails | Risk strategy, roles, board oversight remain organizational decisions; tooling provides evidence artifacts only |
| **Identify (ID)** | ID.AM, ID.RA | ⚠️ | CloudFormation tags (`Project` / `Layer` / `Component`, and volume `DataClassification` = internal / confidential, `templates/storage.yaml`) | Content-level PII scanner (Amazon Comprehend), schema-level field classification | Text/structured-data covered; Office/PDF extraction is outside the companion repository's current scope |
| **Protect (PR)** | PR.AA, PR.DS, PR.PS, PR.IR | ✅ | SnapLock (WORM), MAV (multi-admin verification), TrendAI inline scan, Deep Instinct AI prevention, export-policy/name-mapping hardening, KMS encryption, logically air-gapped vault (documentation only, not verified in this repository) | ONTAP Snapshot, export-policy, Tamperproof Snapshot | Protects the availability and integrity of files and recovery points; does not stop exfiltration through authorised reads (see the exfiltration scenario) |
| **Detect (DE)** | DE.CM, DE.AE | ✅ | ARP/AI configuration (`solutions/ontap-native/`; **also detects writes through an S3 access point**, measured 2026-08-26), FPolicy event capture (**NFS / SMB only**), CloudWatch alarms (`templates/observability.yaml`) | EMS webhook pipeline (~30s), CloudWatch Log Alarm (~90s), FPolicy external server | Behavioral ML baseline delegated to SIEM (Datadog/Elastic/Splunk ML). ARP's documented detection conditions are write-side, and no documented condition fires on reads alone (inference) [E-012]; use audit logs and a SIEM for read-only exfiltration |
| **Respond (RS)** | RS.MA, RS.AN, RS.MI, RS.CO | ✅ | Step Functions orchestration (quarantine, approval workflows), Security Hub integration | Lambda direct blocking (1.8s measured execution; +10-15s for cold start): name-mapping deny + export-policy deny + NACL deny + session disconnect + protective Snapshot, forensics dashboards (4 SIEMs) | Can be triggered from any detection source through SNS. Note: SMB name-mapping deny is ineffective on NTFS security-style volumes |
| **Recover (RC)** | RC.RP, RC.CO | ⚠️ | SnapMirror lag monitoring (`templates/dr-replication.yaml`), DR replication patterns, AWS Backup / logically air-gapped vault (FSx for ONTAP is covered by restore testing, documented) | Verified-clean recovery point (FlexClone + extension scan + verdict), TTL auto-unblock | Full restore rehearsal recommended via AWS Backup restore testing; RC.CO (stakeholder communication) is minimal |

## Scenarios: Encryption and Destruction vs Exfiltration

The same intrusion can lead to files being encrypted or deleted, or to data being read out. Different controls apply, so the two scenarios are described separately in tables of the same shape. Evidence types are given in parentheses inside the cells.

### Encryption and destruction (ransomware)

Read analysis over audit logs and SIEM is for finding exfiltration; it does not stop encryption or deletion in progress.

| Function | Main controls for encryption and destruction | Limits |
|---|---|---|
| GV | Approval of destructive operations (ONTAP MAV, AWS Backup MPA), retention policy, pre-migration protection planning and cost modeling (vault guide) | Governance guidance, not legal judgement |
| ID | Inventory of protected volumes, `DataClassification` tags (`templates/storage.yaml`) | Classification automation is on the companion repository side |
| PR | SnapLock, tamperproof snapshots, MAV, Vscan (TrendAI) / Deep Instinct, logically air-gapped vault (documentation only, documented) | Mechanisms inside the same management boundary do not prepare for a compromise of the whole AWS account (inference; see Management-Plane Compromise) |
| DE | ARP / ARP/AI (write path; also detects writes through S3 Access Points, measured 2026-08-26, ONTAP 9.18.1P3D1), FPolicy (NFS / SMB only [E-015]), scan verdicts | Lag in `attack_probability` updates (existing measurement); learning-period conditions of older ARP (existing text) |
| RS | Approval-based quarantine with Step Functions (this repository; duration not measured). The companion repository's Lambda direct block (within 2 minutes from ARP detection, measured on ONTAP 9.17.1P7D1) | Blast radius of SVM-wide operations |
| RC | Restore from snapshots, SnapMirror or the logically air-gapped vault; check with FlexClone and a scan through S3 Access Points | Outside Malware Protection for AWS Backup [E-008]; temporary recovery points are outside restore testing [E-017] |

### Exfiltration (including double extortion)

SnapLock, tamperproof snapshots and the logically air-gapped vault protect the availability and integrity of recovery points; the confidentiality of data already read out is outside what they protect. ARP's documented detection conditions are write-side, and no documented condition fires on reads alone (inference) [E-012].

| Function | Main controls for exfiltration | Limits |
|---|---|---|
| GV | Minimising the data kept, audit log retention policy, who decides on notification (legal and privacy owners) | Governance guidance, not legal judgement |
| ID | `DataClassification` tags, the companion PII scanner, inventory of volumes published through S3 Access Points | Office / PDF extraction is outside the companion's scope (existing text) |
| PR | S3 Access Points (two layers: IAM access point policy plus file system user; network origin can be limited to a VPC; Block Public Access on by default; documented), export-policy / SMB ACL, SVM separation, KMS (protects the media; does not stop authorised reads) | SnapLock and the logically air-gapped vault do not protect confidentiality |
| DE | File access auditing (requires SACLs; SMB records the first read per object [E-019], documented), S3 Access Points via `Source=S3` / `Source=HTTP` (requester not recorded [E-018], measured), FPolicy (NFS / SMB only [E-015]), SIEM behavioural analysis | No documented ARP condition fires on reads alone (inference) [E-012]; a weak basis for automatic blocking (inference) |
| RS | Evidence preservation, containment per path, handoff ([Data Exfiltration Response Runbook](../runbooks/data-exfiltration-response.md)) | Where the requester is not recorded, identification needs IAM-side records |
| RC | Restoring access settings, RC.CO communication | Recovering data already taken is outside this table |

## Management-Plane Compromise and Recovery Points Outside the Boundary

When an AWS account or an ONTAP administrator credential is compromised, snapshots and backups inside the same management boundary are within reach. The defence is considered in three tiers.

| Tier | Compromise considered | Controls | Evidence type |
|---|---|---|---|
| AWS account | Compromise of an IAM principal, misuse of management APIs | Limit operations with IAM / SCP. CloudTrail records Amazon FSx API calls. GuardDuty detects anomalous behaviour using CloudTrail management events, VPC Flow Logs and Route 53 Resolver DNS query logs as foundational data sources | documented ([logging-using-cloudtrail-win.html](https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/logging-using-cloudtrail-win.html), [guardduty_data-sources.html](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_data-sources.html)) |
| ONTAP administrator | Compromise of an ONTAP administrator credential such as fsxadmin | MAV (multiple approvals for destructive operations), tamperproof snapshots, SnapLock, fsxadmin credential kept in Secrets Manager | documented (MAV, snapshot locking); Secrets Manager is this repository's configuration |
| Outside the boundary | Compromise or closure of the whole AWS account | Logically air-gapped vault, SnapMirror / SnapVault to another account | documented (vault); the degree of isolation of another account is an inference |

The differences between options and how to choose are in the vault guide's [How to Choose an Isolation Option](../data-protection/aws-backup-logically-air-gapped-vault.md#隔離方式の選び方--how-to-choose-an-isolation-option). If you run auto-remediation that revokes external sharing, exclude events raised while copying into the logically air-gapped vault (`userIdentity.invokedBy = backup.amazonaws.com`) (documented).

## Storage-Layer Scope and Boundary

FSx for ONTAP controls act on access to files, objects and blocks (SMB / NFS / S3 Access Points / iSCSI / NVMe/TCP) and on management operations. Whether a query or API call accepted by an application or database is legitimate is decided in the application layer and is not observable from the storage layer [E-013]. When a database sits on an iSCSI or NVMe LUN, ONTAP sees blocks (inference). What the storage layer can provide is threefold: access control and auditing as a file store, recovery points against tampering, deletion and encryption, and isolated copies against a management-plane compromise. As references outside this scope, see [AWS WAF](https://docs.aws.amazon.com/waf/latest/developerguide/) and [Amazon Inspector](https://docs.aws.amazon.com/inspector/latest/user/what-is-inspector.html).

## NIST SP 800-61r3 Incident Handling Lifecycle

The project maps to SP 800-61's incident handling phases as follows:

```
┌────────────────────────────────────────────────────────────────────────────┐
│                        NIST SP 800-61r3 Lifecycle                           │
├──────────────┬──────────────┬──────────────────────┬──────────────────────┤
│  Preparation │  Detection & │  Containment,        │  Post-Incident       │
│              │  Analysis    │  Eradication &       │  Activity            │
│              │              │  Recovery            │                      │
├──────────────┼──────────────┼──────────────────────┼──────────────────────┤
│ • SnapLock   │ • ARP/AI     │ • SMB user block     │ • Forensics          │
│ • MAV        │ • FPolicy    │   (name-mapping deny)│   dashboards         │
│ • TrendAI    │ • EMS        │ • NFS IP block       │ • Compliance         │
│   inline     │   webhook    │   (export-policy     │   evidence pack      │
│   scan       │ • CloudWatch │   + NACL deny)       │ • Verified-clean     │
│ • Deep       │   Log Alarm  │ • Session disconnect │   recovery point     │
│   Instinct   │ • SIEM ML    │ • Protective         │ • Audit log          │
│ • Export-    │   (delegated)│   Snapshot           │   retention          │
│   policy     │              │ • Step Functions     │ • Lessons learned    │
│   hardening  │              │   quarantine         │   (manual)           │
│ • KMS        │              │ • TTL auto-unblock   │                      │
│   encryption │              │                      │                      │
└──────────────┴──────────────┴──────────────────────┴──────────────────────┘
```

**CSF 2.0 vs SP 800-61 relationship**: CSF 2.0 is the organization-wide risk-management wheel that Govern sits above; SP 800-61 is the tactical incident-handling lifecycle that CSF's Detect/Respond/Recover functions delegate to during an actual event. The diagram above nests SP 800-61 phases within the relevant CSF functions.

## NIST IR 8374r1 — Ransomware-Specific Outcomes

[NIST IR 8374r1](https://csrc.nist.gov/pubs/ir/8374/r1/final) maps ransomware-specific outcomes to CSF 2.0 functions. This project addresses the following:

| IR 8374r1 Outcome | Implementation |
|-------------------|---------------|
| **Detect ransomware file manipulation** | ARP/AI entropy + extension-change detection (ONTAP native, no learning period on 9.16.1+) |
| **Limit propagation** | Approval-based SMB/NFS access quarantine with Step Functions (this repository; duration not measured). The companion repository's Lambda direct block lands within 2 minutes of ARP detection (measured on ONTAP 9.17.1P7D1) |
| **Maintain immutable backups** | SnapLock WORM volumes, Tamperproof Snapshots (deletion refused until retention expires, including for administrators), logically air-gapped vault (documentation only; [vault guide](../data-protection/aws-backup-logically-air-gapped-vault.md)) |
| **Verify backup integrity before restore** | FlexClone + isolated S3 AP scan for ransomware-associated extensions. Malware Protection for AWS Backup does not scan FSx for ONTAP recovery points [E-008] |
| **Rapid recovery** | FlexClone for isolated verification of a candidate Snapshot (space-efficient, copy-on-write); actual restore via `volume snapshot restore` or FlexClone promotion is a separate operation |
| **Evidence preservation** | Protective Snapshot at incident time + CloudWatch Logs audit trail (note: pre-action state not yet captured — chain-of-custody gap) |

## MITRE ATT&CK Mapping

| ATT&CK Technique | ID | Project Response |
|------------------|----|--------------------|
| Data Encrypted for Impact | T1486 | ARP/AI detection → automated blocking (name-mapping deny + export-policy deny + NACL deny) |
| Inhibit System Recovery | T1490 | SnapLock (undeletable) + Tamperproof Snapshot (locked until expiry, including for administrators) + logically air-gapped vault (recovery points outside the management boundary, documentation only) |
| Data Destruction | T1485 | FPolicy real-time file operation detection → EventBridge → Step Functions quarantine. **Coverage is NFS / SMB only — writes arriving through an S3 access point do not reach FPolicy** (measured 2026-08-26, ONTAP 9.18.1P3D1). ARP covers that path |
| Account Manipulation | T1098 | Multi-Admin Verification (MAV) — critical admin operations require multi-admin approval |
| Valid Accounts | T1078 | Audit log pipeline (full access traceability) + CloudWatch Log Alarm — detection/visibility control, not prevention |
| Data from Cloud Storage | T1530 | Reads through S3 Access Points. Narrow them with the access point policy and IAM. The ONTAP audit log records the operation with `Source=HTTP` / `Source=S3` (requester not recorded [E-018]) |
| Exfiltration Over Web Service | T1567 | Detection is not a storage-layer role; SIEM and network-side monitoring (exfiltration scenario) |
| Exploit Public-Facing Application | T1190 | Outside the storage layer (Storage-Layer Scope and Boundary) |
| Server Software Component: Web Shell | T1505.003 | If the web server's files sit on a file store scanned by TrendAI / Deep Instinct, they are inspected on write (inference) |
| Create Account | T1136 | CloudTrail (IAM operations). Creating an ONTAP administrator account (`security login create`) can be protected by a MAV rule (documented) |

## AWS Well-Architected Alignment

| Well-Architected Pillar | Relevant Components |
|------------------------|-------------------|
| **Security** | IAM least-privilege (per-Lambda roles), encryption at rest (KMS), encryption in transit (TLS to ONTAP REST API), VPC isolation, Security Hub integration |
| **Reliability** | Multi-AZ FSx for ONTAP, SnapMirror cross-region replication, DLQ for failed response actions, CloudWatch alarms on pipeline health, AWS Backup logically air-gapped vault (documentation only) |
| **Cost Optimization** | `templates/cost-scheduler.yaml` (dev/staging auto stop/start), response module cost ~$0.51/month |
| **Operational Excellence** | CloudFormation IaC, CI/CD pipeline (285 tests), cfn-guard security policies |

## CIS Controls v8 Mapping

| CIS Control | Implementation in This Project |
|-------------|-------------------------------|
| **Control 3**: Data Protection | KMS encryption, SnapLock WORM, Tamperproof Snapshot. Confidentiality comes from encryption and access control; WORM protects integrity |
| **Control 8**: Audit Log Management | S3 AP audit pipeline (365-day retention), CloudWatch Logs |
| **Control 11**: Data Recovery | Snapshot + SnapMirror + verified recovery point, logically air-gapped vault and restore testing |
| **Control 13**: Network Monitoring | FPolicy (NFS / SMB only) + CloudWatch + VPC Flow Logs |
| **Control 17**: Incident Response Management | Automated blocking + Step Functions orchestration + DLQ alarm |

## Governance Reporting Guidance

When positioning this project's capabilities to a risk committee, compliance officer, or board:

### Appropriate framing

> "Approval-based quarantine in the Respond phase (Step Functions) and Recover-phase pre-validation are implemented; paired with the companion observability repository, the storage-layer block lands in under 2 minutes from ARP detection (measured on ONTAP 9.17.1P7D1). Govern-phase maturity and the behavioral ML side of Detect are tracked separately"

### Inappropriate framing

> "Ransomware protection is complete" — this covers Respond deeply and contributes to four other functions; Govern remains an organizational responsibility

> "Isolated backups mean we are also prepared for a leak." Isolated backups (the logically air-gapped vault, SnapLock, tamperproof snapshots) address the availability and integrity of recovery points; the confidentiality of data already read out is handled by other controls (access control, encryption, auditing). Decisions such as whether to notify belong to legal owners, and this guidance is not legal judgement

### Available evidence artifacts

- CloudFormation deployment records (who deployed what and when)
- CloudWatch Logs (trigger source, action taken, API response)
- DynamoDB verdict records (recovery verification pass/fail)
- SNS notification trails (who was notified, what, when)

### Audit-trail limitations

- The response pipeline logs post-action state but does not currently capture pre-action state (name-mapping/export-policy configuration before the block was applied)
- The SNS trigger message itself is not hashed
- These gaps need addressing if protective Snapshots are intended to serve as formal investigation evidence (chain of custody)

> **Note on status markers**: ✅ indicates a capability is technically implemented and E2E-verified in this codebase. It does not represent compliance certification against any specific regulatory program (FedRAMP, ISMAP, HIPAA, PCI DSS, SOC 2, etc.). Treat these markers as one input when mapping your control requirements to available technical capabilities. Items marked documentation-only are not part of the basis for ✅.

## Operational Considerations

Key caveats:

- **RTO/RPO**: This project does not define fixed RTO/RPO numbers. Those are environment-specific and must be established by each deployment based on business requirements. The measured E2E timing of the companion repository's response module (Lambda) (under 2 min detect-to-block, under 3 min worst-case) provides a data point for your RPO calculation, not a guaranteed SLA. The duration of this repository's Step Functions quarantine has not been measured.
- **False-positive handling**: Automated blocking carries inherent false-positive risk. The TTL auto-unblock companion stack limits lockout duration. Always test with non-production users first.
- **Blast radius**: Both SMB name-mapping deny and NFS export-policy deny are **SVM-wide** — they affect all volumes and shares within the target SVM. Factor this into multi-tenant SVM designs.
- **Same-subnet NACL limitation**: NACL deny rules only apply to traffic crossing subnet boundaries. If attacker client and FSx for ONTAP ENIs are in the same subnet, only the export-policy deny is effective.
- **Data exfiltration gap**: ARP/AI's documented detection conditions are write-side, such as file encryption (entropy + extension change), and no documented condition fires on reads alone, so read-only exfiltration without encryption is not expected to trigger it (inference) [E-012]. FPolicy covers NFS / SMB only [E-015]. Reads through S3 Access Points appear in the ONTAP native audit log with `Source=HTTP` / `Source=S3`, but the requester is not recorded [E-018]. Use audit logs and SIEM behavioural analytics; the procedure is the [exfiltration runbook](../runbooks/data-exfiltration-response.md).
- **Domain Admin bypass**: Users in `FileSystemAdministratorsGroup` bypass name-mapping deny rules entirely. Always test with non-admin users.
- **Privacy in response logs**: Response logs contain personal data (username, domain, client IP). Apply appropriate access controls and retention policies per your data protection requirements.
- **Evidence retention and deletion permissions**: Set a retention period on the CloudWatch Logs log groups and restrict who can delete them with IAM. Whether the trail resists tampering depends on the storage mechanism behind it (see the audit log destination item in the [exfiltration runbook](../runbooks/data-exfiltration-response.md)).
- **Auto-remediation and AWS Backup**: Auto-remediation that revokes external sharing (EventBridge + Lambda) can make copies into the logically air-gapped vault fail. Exclude events with `userIdentity.invokedBy = backup.amazonaws.com` (documented, [vault guide](../data-protection/aws-backup-logically-air-gapped-vault.md)).
- **NFS client-side caching**: Export-policy deny takes effect immediately server-side, but Linux NFS clients cache access decisions for up to 60 seconds (`actimeo`). NACL deny (cross-subnet) provides immediate packet-level blocking that bypasses client caching.
- **Rollback/undo path**: False-positive blocks can be reversed via CLI (`unblock-smb` or `unblock-nfs`). The TTL auto-unblock stack also removes blocks after a configurable duration.
- **NTFS volume alternatives**: For NTFS security-style volumes, use AD account disable, NTFS ACL removal, or NACL deny instead of name-mapping.
- **Zero Trust alignment**: Implements deny-by-default, verify explicitly, and assume breach. Does not implement file-level microsegmentation.
- **AWS-specific**: Orchestration uses AWS-native services (Lambda, Step Functions, CloudFormation). ONTAP REST API patterns are portable; the automation layer is not.
- **Single-point-of-failure awareness**: The response pipeline (SNS → Lambda → ONTAP REST API) depends on IAM role integrity and network reachability. If the Lambda's execution role is compromised or VPC connectivity to ONTAP is lost, the entire automated response is disabled. DLQ alarms detect failed executions, but cannot detect a completely silenced invocation (e.g., SNS subscription removed).
- **Data residency**: Response logs and audit trails remain in the AWS Region where the stack is deployed. For multi-region requirements, deploy per-region stacks independently. See the companion repo's [data-residency guide](https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations/blob/main/docs/en/data-residency.md) for additional guidance.

## References

- [NIST Cybersecurity Framework (CSF) 2.0](https://www.nist.gov/cyberframework)
- [NIST SP 800-61r3 — Incident Handling Guide](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [NIST IR 8374r1 — Ransomware Risk Management: A CSF 2.0 Community Profile](https://csrc.nist.gov/pubs/ir/8374/r1/final)
- [AWS — Ransomware Risk Management on AWS Using the NIST CSF](https://docs.aws.amazon.com/whitepapers/latest/ransomware-risk-management-on-aws-using-nist-csf/technical-capabilities.html)
- [AWS Backup — Restore testing](https://docs.aws.amazon.com/aws-backup/latest/devguide/restore-testing.html)
- [Elastio — Mapping Ransomware Recovery to NIST CSF 2.0](https://elastio.com/blog/mapping-ransomware-recovery-to-nist-csf-20)
- [NetApp — Fortify your cybersecurity defenses with NIST framework](https://www.netapp.com/it/blog/fortify-cybersecurity-nist-framework/)
- [NIST CSWP 29: The NIST Cybersecurity Framework (CSF) 2.0](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf)
- [IPA: Information Security 10 Major Threats 2026 (Japanese)](https://www.ipa.go.jp/security/10threats/10threats2026.html)
- [MITRE ATT&CK: Enterprise Techniques](https://attack.mitre.org/techniques/enterprise/)
- [AWS What's New: AWS Backup adds logically air-gapped vault support for Amazon FSx for NetApp ONTAP](https://aws.amazon.com/about-aws/whats-new/2026/09/aws-backup-air-gapped-vault-fsx-ontap/)
- [AWS Storage Blog: Planning data protection before migration](https://aws.amazon.com/blogs/storage/planning-data-protection-before-migration-how-aws-storage-assessments-model-backup-and-disaster-recovery-costs/)
- [AWS Backup: Logically air-gapped vault](https://docs.aws.amazon.com/aws-backup/latest/devguide/logicallyairgappedvault.html)

## Related Documents

- [companion-repos-integration.md](companion-repos-integration.md) — Layer mapping with the observability repo
- [related-articles.md](related-articles.md) — Related articles index
- [AWS Backup Logically Air-Gapped Vault](../data-protection/aws-backup-logically-air-gapped-vault.md): how to choose an isolation option
- [Data Exfiltration Response Runbook](../runbooks/data-exfiltration-response.md): steps when exfiltration is suspected
- [Operational Considerations](operational-considerations.md)
- [Cyber Resilience Capability Map (companion repo)](https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations/blob/main/docs/en/cyber-resilience-capability-map.md) — Full 6-function mapping with alternative implementation paths and vendor-neutral comparison

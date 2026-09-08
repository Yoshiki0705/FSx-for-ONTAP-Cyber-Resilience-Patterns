# Cyber Resilience Framework Mapping

> **Executive summary**: This project covers NIST CSF 2.0 Respond (automated containment in under 2 min) and Protect (immutable storage, inline scanning) most deeply, contributes to Detect and Identify, and explicitly leaves Govern as an organizational responsibility. Key known limitations: no behavioral ML (delegated to SIEM), no NTFS-volume SMB blocking, no data-exfiltration-only detection.

This repository is designed against [NIST Cybersecurity Framework (CSF) 2.0](https://www.nist.gov/cyberframework), with additional alignment to [NIST SP 800-61r3](https://csrc.nist.gov/pubs/sp/800/61/r3/final) (Incident Handling) and [NIST IR 8374r1](https://csrc.nist.gov/pubs/ir/8374/r1/final) (Ransomware Risk Management).

## NIST CSF 2.0 Function Coverage

| CSF 2.0 Function | Status | This Repo | Companion Repo ([observability](https://github.com/Yoshiki0705/fsxn-observability-integrations)) | Gap / Organizational Responsibility |
|-------------------|:------:|-----------|---------------------|-----|
| **Govern (GV)** | ⚠️ | CloudFormation-as-code audit trail, cfn-guard compliance rules, `solutions/compliance/` evidence collection | CloudWatch Logs + SNS notification trails | Risk strategy, roles, board oversight remain organizational decisions; tooling provides evidence artifacts only |
| **Identify (ID)** | ✅ | Data classification matrix (`docs/`), asset tagging via CFn | Content-level PII scanner (Amazon Comprehend), schema-level field classification | Text/structured-data covered; Office/PDF extraction not yet implemented |
| **Protect (PR)** | ✅ | SnapLock (WORM), MAV (multi-admin verification), TrendAI inline scan, Deep Instinct AI prevention, export-policy/name-mapping hardening, KMS encryption | ONTAP Snapshot, export-policy, Tamperproof Snapshot | Full for storage-layer safeguards |
| **Detect (DE)** | ✅ | ARP/AI configuration (`solutions/ontap-native/`; **also detects writes through an S3 access point**, measured 2026-08-26), FPolicy event capture (**NFS / SMB only**), CloudWatch alarms (`templates/observability.yaml`) | EMS webhook pipeline (~30s), CloudWatch Log Alarm (~90s), FPolicy external server | Behavioral ML baseline delegated to SIEM (Datadog/Elastic/Splunk ML) |
| **Respond (RS)** | ✅ | Step Functions orchestration (quarantine, approval workflows), Security Hub integration | Lambda direct blocking (1.8s measured execution; +10-15s for cold start): name-mapping deny + export-policy deny + NACL deny + session disconnect + protective Snapshot, forensics dashboards (4 SIEMs) | Full for mitigation tooling (source-agnostic via SNS). Note: SMB name-mapping deny is ineffective on NTFS security-style volumes |
| **Recover (RC)** | ⚠️ | SnapMirror lag monitoring (`templates/dr-replication.yaml`), DR replication patterns | Verified-clean recovery point (FlexClone + extension scan + verdict), TTL auto-unblock | Full restore rehearsal recommended via AWS Backup restore testing; RC.CO (stakeholder communication) is minimal |

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
| **Limit propagation** | Automated SMB/NFS access blocking within 2 minutes of detection |
| **Maintain immutable backups** | SnapLock WORM volumes, Tamperproof Snapshots (cannot be deleted by compromised admin) |
| **Verify backup integrity before restore** | FlexClone + isolated S3 AP scan for ransomware-associated extensions |
| **Rapid recovery** | FlexClone for isolated verification of a candidate Snapshot (space-efficient, copy-on-write); actual restore via `volume snapshot restore` or FlexClone promotion is a separate operation |
| **Evidence preservation** | Protective Snapshot at incident time + CloudWatch Logs audit trail (note: pre-action state not yet captured — chain-of-custody gap) |

## MITRE ATT&CK Mapping

| ATT&CK Technique | ID | Project Response |
|------------------|----|--------------------|
| Data Encrypted for Impact | T1486 | ARP/AI detection → automated blocking (name-mapping deny + export-policy deny + NACL deny) |
| Inhibit System Recovery | T1490 | SnapLock (undeletable) + Tamperproof Snapshot (even admin cannot tamper) |
| Data Destruction | T1485 | FPolicy real-time file operation detection → EventBridge → Step Functions quarantine. **Coverage is NFS / SMB only — writes arriving through an S3 access point do not reach FPolicy** (measured 2026-08-26, ONTAP 9.18.1P3D1). ARP covers that path |
| Account Manipulation | T1098 | Multi-Admin Verification (MAV) — critical admin operations require multi-admin approval |
| Valid Accounts | T1078 | Audit log pipeline (full access traceability) + CloudWatch Log Alarm — detection/visibility control, not prevention |

## AWS Well-Architected Alignment

| Well-Architected Pillar | Relevant Components |
|------------------------|-------------------|
| **Security** | IAM least-privilege (per-Lambda roles), encryption at rest (KMS), encryption in transit (TLS to ONTAP REST API), VPC isolation, Security Hub integration |
| **Reliability** | Multi-AZ FSx for ONTAP, SnapMirror cross-region replication, DLQ for failed response actions, CloudWatch alarms on pipeline health |
| **Cost Optimization** | `templates/cost-scheduler.yaml` (dev/staging auto stop/start), response module cost ~$0.51/month |
| **Operational Excellence** | CloudFormation IaC, CI/CD pipeline (285 tests), cfn-guard security policies |

## CIS Controls v8 Mapping

| CIS Control | Implementation in This Project |
|-------------|-------------------------------|
| **Control 3**: Data Protection | KMS encryption, SnapLock WORM, Tamperproof Snapshot |
| **Control 8**: Audit Log Management | S3 AP audit pipeline (365-day retention), CloudWatch Logs |
| **Control 11**: Data Recovery | Snapshot + SnapMirror + verified recovery point |
| **Control 13**: Network Monitoring | FPolicy (NFS / SMB only) + CloudWatch + VPC Flow Logs |
| **Control 17**: Incident Response Management | Automated blocking + Step Functions orchestration + DLQ alarm |

## Governance Reporting Guidance

When positioning this project's capabilities to a risk committee, compliance officer, or board:

### Appropriate framing

> "Automated Respond-phase containment (under 2 min) with Recover-phase pre-validation implemented; Govern-phase maturity and the behavioral ML side of Detect are tracked separately"

### Inappropriate framing

> "Ransomware protection is complete" — this covers Respond deeply and contributes to four other functions; Govern remains an organizational responsibility

### Available evidence artifacts

- CloudFormation deployment records (who deployed what and when)
- CloudWatch Logs (trigger source, action taken, API response)
- DynamoDB verdict records (recovery verification pass/fail)
- SNS notification trails (who was notified, what, when)

### Audit-trail limitations

- The response pipeline logs post-action state but does not currently capture pre-action state (name-mapping/export-policy configuration before the block was applied)
- The SNS trigger message itself is not hashed
- These gaps need addressing if protective Snapshots are intended to serve as formal investigation evidence (chain of custody)

> **Note on status markers**: ✅ indicates a capability is technically implemented and E2E-verified in this codebase. It does not represent compliance certification against any specific regulatory program (FedRAMP, ISMAP, HIPAA, PCI DSS, SOC 2, etc.). Treat these markers as one input when mapping your control requirements to available technical capabilities.

## Operational Considerations

Key caveats identified through multi-stakeholder review:

- **RTO/RPO**: This project does not define fixed RTO/RPO numbers — those are environment-specific and must be established by each deployment based on business requirements. The response module's measured E2E timing (under 2 min detect-to-block, under 3 min worst-case) provides a data point, not a guaranteed SLA.
- **False-positive handling**: Automated blocking carries inherent false-positive risk. The TTL auto-unblock companion stack limits lockout duration. Always test with non-production users first.
- **Blast radius**: Both SMB name-mapping deny and NFS export-policy deny are **SVM-wide** — they affect all volumes and shares within the target SVM. Factor this into multi-tenant SVM designs.
- **Same-subnet NACL limitation**: NACL deny rules only apply to traffic crossing subnet boundaries. If attacker client and FSx for ONTAP ENIs are in the same subnet, only the export-policy deny is effective.
- **Data exfiltration gap**: ARP/AI detects file encryption but not data exfiltration without encryption (pure data theft). FPolicy-based monitoring and SIEM behavioral analytics cover this gap partially — **and only for NFS / SMB**: a read through an S3 access point does not reach FPolicy (measured 2026-08-26). Tracing such reads means the ONTAP native audit log (`Source=HTTP` / `Source=S3`), which records the operation but not the requester.
- **Domain Admin bypass**: Users in `FileSystemAdministratorsGroup` bypass name-mapping deny rules entirely. Always test with non-admin users.
- **Privacy in response logs**: Response logs contain personal data (username, domain, client IP). Apply appropriate access controls and retention policies per your data protection requirements.
- **Evidence tamper-resistance**: CloudWatch Logs in immutable retention mode provides tamper-resistant storage for response audit trails.
- **NFS client-side caching**: Export-policy deny takes effect immediately server-side, but Linux NFS clients cache access decisions for up to 60 seconds (`actimeo`). NACL deny (cross-subnet) provides immediate packet-level blocking that bypasses client caching.
- **Rollback/undo path**: False-positive blocks can be reversed via CLI (`unblock-smb` or `unblock-nfs`). The TTL auto-unblock stack also removes blocks after a configurable duration.
- **NTFS volume alternatives**: For NTFS security-style volumes, use AD account disable, NTFS ACL removal, or NACL deny instead of name-mapping.
- **Zero Trust alignment**: Implements deny-by-default, verify explicitly, and assume breach. Does not implement file-level microsegmentation.
- **AWS-specific**: Orchestration uses AWS-native services (Lambda, Step Functions, CloudFormation). ONTAP REST API patterns are portable; the automation layer is not.
- **Single-point-of-failure awareness**: The response pipeline (SNS → Lambda → ONTAP REST API) depends on IAM role integrity and network reachability. If the Lambda's execution role is compromised or VPC connectivity to ONTAP is lost, the entire automated response is disabled. DLQ alarms detect failed executions, but cannot detect a completely silenced invocation (e.g., SNS subscription removed).
- **Data residency**: Response logs and audit trails remain in the AWS Region where the stack is deployed. For multi-region requirements, deploy per-region stacks independently. See the companion repo's [data-residency guide](https://github.com/Yoshiki0705/fsxn-observability-integrations/blob/main/docs/en/data-residency.md) for additional guidance.

## References

- [NIST Cybersecurity Framework (CSF) 2.0](https://www.nist.gov/cyberframework)
- [NIST SP 800-61r3 — Incident Handling Guide](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [NIST IR 8374r1 — Ransomware Risk Management: A CSF 2.0 Community Profile](https://csrc.nist.gov/pubs/ir/8374/r1/final)
- [AWS — Ransomware Risk Management on AWS Using the NIST CSF](https://docs.aws.amazon.com/whitepapers/latest/ransomware-risk-management-on-aws-using-nist-csf/technical-capabilities.html)
- [AWS Backup — Restore testing](https://docs.aws.amazon.com/aws-backup/latest/devguide/restore-testing.html)
- [Elastio — Mapping Ransomware Recovery to NIST CSF 2.0](https://elastio.com/blog/mapping-ransomware-recovery-to-nist-csf-20)
- [NetApp — Fortify your cybersecurity defenses with NIST framework](https://www.netapp.com/it/blog/fortify-cybersecurity-nist-framework/)

## Related Documents

- [companion-repos-integration.md](companion-repos-integration.md) — Layer mapping with the observability repo
- [related-articles.md](related-articles.md) — Related articles index
- [Cyber Resilience Capability Map (companion repo)](https://github.com/Yoshiki0705/fsxn-observability-integrations/blob/main/docs/en/cyber-resilience-capability-map.md) — Full 6-function mapping with alternative implementation paths and vendor-neutral comparison

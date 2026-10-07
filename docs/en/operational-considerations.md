# Operational Considerations

Key caveats for production deployments of FSx for ONTAP Cyber Resilience Patterns.

## Response Timing & SLA

- **RTO/RPO**: This project does not define fixed RTO/RPO numbers — those are environment-specific and must be established by each deployment based on business requirements. The response module's measured E2E timing (under 2 min detect-to-block, under 3 min worst-case) provides a data point for your RPO calculation, not a guaranteed SLA.

## False Positives & Auto-Unblock

- **False-positive handling**: Automated blocking carries inherent false-positive risk. The TTL auto-unblock companion stack (`automated-response-ttl.yaml`) limits lockout duration. Always test with non-production users first, and tune upstream detection rules before connecting them to the response pipeline.
- **Rollback/undo path**: If an automated block is a false positive, unblock via CLI (`automated-response-cli.sh unblock-smb --domain <CORP> --user <user>` or `unblock-nfs --ip <ip>`). The TTL auto-unblock stack also removes blocks after a configurable duration automatically.

## Blast Radius & Scope

- **SVM-wide blocking**: Both SMB name-mapping deny and NFS export-policy deny are **SVM-wide** — they affect all volumes and shares within the target SVM, not just the specified volume. Factor this into multi-tenant SVM designs.
- **Same-subnet NACL limitation**: NACL deny rules only apply to traffic crossing subnet boundaries. If the attacker's client and FSx for ONTAP ENIs are in the same subnet, the NACL has no effect — the export-policy deny (ONTAP-layer) is the only blocking mechanism in that scenario.
- **NFS client-side caching**: Export-policy deny takes effect immediately on the ONTAP server, but Linux NFS clients cache access decisions for up to 60 seconds (`actimeo` default). During this window, an already-mounted client may still perform I/O. The NACL deny rule (for cross-subnet scenarios) provides immediate packet-level blocking that bypasses client caching entirely.

## Detection Gaps

- **Data exfiltration gap**: ARP/AI takes write-side behaviour such as file encryption (entropy + extension changes) as input, and read-only exfiltration without encryption is not among its detection premises [E-012]. FPolicy receives NFS / SMB operations only [E-015]. Reads through S3 Access Points appear in the ONTAP audit log with `Source=S3` / `Source=HTTP`, but the requester is not recorded [E-018] (measured 2026-08-26, ONTAP 9.18.1P3D1). Use audit logs and SIEM behavioural analytics; the procedure is the [Data Exfiltration Response Runbook](../runbooks/data-exfiltration-response.md).
- **Domain Admin bypass**: Users who are members of `FileSystemAdministratorsGroup` (typically Domain Admins) bypass name-mapping deny rules entirely. Always test blocking with non-admin users.

## Volume Security Style

- **NTFS volume alternatives**: For volumes using NTFS security style (where name-mapping deny is ineffective), consider: (1) disabling the user's AD account directly, (2) removing the user from NTFS share/file permissions, or (3) using NACL deny rules for network-layer blocking.

## Privacy & Audit

- **Privacy in response logs**: Automated response logs (CloudWatch Logs, SNS messages) contain personal data (username, domain, client IP). Apply appropriate access controls and retention policies.
- **Evidence retention and deletion permissions**: Set a retention period on the CloudWatch Logs log groups and restrict who can delete them with IAM. Whether the trail resists tampering depends on the storage mechanism behind it (see the audit log destination item in the [Data Exfiltration Response Runbook](../runbooks/data-exfiltration-response.md)).

## Architecture Scope

- **Zero Trust alignment**: This architecture implements several Zero Trust principles — deny-by-default (export-policy/name-mapping), verify explicitly (per-request ACL evaluation), assume breach (automated containment + evidence preservation). It does not implement microsegmentation at the file level.
- **AWS-specific implementation**: This project uses AWS-native services (Lambda, Step Functions, CloudFormation, CloudWatch, SNS, EventBridge). It is not directly portable to other cloud providers. The ONTAP REST API patterns are portable across any ONTAP deployment, but the orchestration and automation layer is AWS-specific.

## Data Protection & Isolated Copies

- **File system encryption key**: To copy backups to an AWS Backup logically air-gapped vault, the source file system must be encrypted with a customer managed key [E-009]. This is a different key from the vault's own encryption key (an AWS owned key by default). For a file system on an AWS managed key, the backup job does not fail; it ends "Completed with issues" and the backup stays only in the standard vault (documented, [lag-vault-primary-backup.html](https://docs.aws.amazon.com/aws-backup/latest/devguide/lag-vault-primary-backup.html)). Check that the copy exists in the vault, not only the job status.
- **Backup scope**: FSx for ONTAP volume backups cover RW volumes; DP, LSM, FlexCache and SnapMirror destination volumes and SnapLock FlexGroup volumes are not backed up [E-010].
- **Interaction with auto-remediation**: Auto-remediation that revokes external sharing (EventBridge + Lambda) can make copies into the logically air-gapped vault fail. Exclude events with `userIdentity.invokedBy = backup.amazonaws.com` (documented). See the [vault guide](../data-protection/aws-backup-logically-air-gapped-vault.md).

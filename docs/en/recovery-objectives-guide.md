# Recovery time and recovery point objectives are values the service owner sets from measurements in its own environment
> **Summary**: This guide covers adopting the second pillar, RTO/RPO and SLA/SLO/SLI. It defines the start and end of an RTO, describes each recovery layer and how to choose among them, gives the steps for setting SLIs and SLOs, explains how to handle infrequent events and restore drills, and specifies the format of the recovery point record handed to the third pillar. Every numeric example is an example and a promise to no end user. Measured values go to the [measurement results](recovery-measurement-results.md). This guide quotes only finished measurements, with their environment and count, and says so where a measurement is not finished.
## Definitions: the service owner's values and the vendor SLA kept apart
RTO (recovery time objective), RPO (recovery point objective), SLA, SLO and SLI are values that the service owner, the party that provides a service to end users, sets for those end users. They are separate from the vendor SLA that AWS or NetApp publishes for its own services. A vendor SLA is one input to the service owner's SLO and does not replace it. This guide writes no vendor SLA figure. When you use one, quote it from the vendor's published SLA page and add the reference date.
This project does not decide the values. It provides the definitions needed to decide them, the measured values to use as input, the steps for setting them, and reference configurations. The values and examples in this guide are references for the service owner to replace with its own, and they are a promise to no end user. This guide is governance guidance, not a legal, contractual or regulatory judgment. The contractual commitments of an SLA are the service owner's own decision.
The table below separates who decides what and who provides what.
| Category | Content | Source |
|---|---|---|
| Values the service owner decides | RTO, RPO, the target values and measurement window of each SLO, and what to do when the error budget is used up | The service owner's judgment |
| Terms this project defines | The RTO time points and intervals, how to measure each SLI, and the format of the recovery point record | The sections of this guide from "Definition of the RTO time points and intervals" onward |
| Measured values this project provides | Restore and rebuild durations on one verification file system in the Tokyo Region | [Measurement results](recovery-measurement-results.md) |
| Steps and scripts this project provides | How to measure the intervals in your own environment, dry-run, and safety guards | README of the measurement scripts (`benchmarks/recovery/README.md`, not yet on the main branch) |
This pillar maps to REL13-BP01, REL13-BP02 and OPS09-BP01 of the AWS Well-Architected Framework [2], [3], [4]. The mapping table is in the framework mapping under [Mapping to best practice IDs](cyber-resilience-framework-mapping.md#best-practice-ids) and is not copied here. In the Resilience lifecycle framework of AWS Prescriptive Guidance [1], this pillar corresponds to Set objectives and Evaluate and test. The mapping to PDCA is in the programme document under [Resilience lifecycle stages](cyber-resilience-programme.md#resilience-lifecycle-stages) and is not copied here.
## Definition of the RTO time points and intervals
An RTO is not a value until its start and end are fixed. The table below divides a recovery into eight time points.
| Time point | Definition | Source | Treatment in this project |
|---|---|---|---|
| T0 | Impact begins (the first effect of the compromise or failure) | Operational records (estimate) | Not measured |
| T1 | Detection | Time the alarm fired | Existing records quoted (below) |
| T2 | Recovery declared (the moment it was decided to begin the recovery decision) | `declared_at` of the restore record | Start of the reference RTO |
| T3 | Recovery point decided | `decided_at` of the decision record | A field of the record |
| T4 | Restore operation starts | Start time of the operation (ONTAP job, `StartRestoreJob`, stack creation) | Measured |
| T5 | Data available (the time the quick check matched the manifest) | Client clock. `restore.data_available_at` of the restore record | Measured |
| T6 | Acceptance check complete (the application responds as expected and the service owner's check is done) | Application response, operational records. `restore.accepted_at` of the restore record | Measured up to the application response. The service owner's acceptance is not measured |
| T7 | Cutover complete (users start using the recovered environment) | Operational records | Not measured |
The span between two adjacent time points is an interval. An interval is computed only from two times taken on the same clock. An interval that crosses two clocks carries the offset between the clocks as its error.
| Interval | Formula | Treatment in this project |
|---|---|---|
| S_detect | T1 − T0 | Not measured |
| S_declare | T2 − T1 | Existing records quoted (below) |
| S_decide | T3 − T2 (`decided_at` − `declared_at`) | Computed from the two recovery point records (operations) |
| S_prepare | T4 − T3 | Not measured (operations) |
| S_restore | T5 − T4 | Measured (Snapshot restore, FSx backup restore, AWS Backup restore testing, SnapMirror) |
| S_rebuild | In a clean rebuild, from recreating the compute and reattaching the same volume until the data can be read | Measured (<!-- TODO(13.2): after M4 is final, link the per-interval values -->) |
| S_accept | T6 − T5 | Within the rebuild measurement, up to the application response |
| S_cutover | T7 − T6 | Not measured |
T5 is the time at which the size of every file and the SHA-256 of the first and last 4 MiB matched the manifest. The match of the SHA-256 of every file in full is a separate time, `full_check_done_at`, and is used as the condition for a measurement record to count as successful.
Wherever an RTO value is written, name its start and end in parentheses, for example "RTO (T2→T6)". An RTO with no start or end, such as "RTO 4 hours", is not used in this guide or in its examples. "RTO (T2→T6)" is neither the length of the outage that end users experience (T0 to T7) nor the vendor's indicative duration of an operation (the range from T4 to T5). It is a different quantity.
| RTO definition | Start and end | When to use |
|---|---|---|
| Reference definition | RTO (T2→T6). Includes S_decide | You want the time to decide the recovery point inside the objective |
| Definition without S_decide | RTO (T3→T6) | The decision on the recovery point is managed under a separate objective (an investigation objective) |
The reference definition runs from the recovery declaration (T2) to the completion of the acceptance check (T6), and shows S_decide in a separate row of the table. The service owner replaces this definition with its own start and end. Whether S_decide belongs in the RTO is the service owner's decision. The value that includes it (T2 to T6) and the value that excludes it (T3 to T6) can both be computed from the two recovery point records (section "Hand-over format to the third pillar"). This definition is the answer to the question the programme document left to the second pillar, whether the time to decide the recovery point counts in the RTO ([Order of work](cyber-resilience-programme.md#order-of-work)).
For S_detect and S_declare, use the existing measurements of detection to notification and do not re-measure them in this project. They are the Cyber [alert path verification](alert-path-verification.md) (2026-11-13, ap-northeast-1, one run each) and the Observability E2E measurement (about 30 seconds to an EMS notification).
The AWS reference approach runs the investigation, the validation of candidates and the infrastructure rebuild in parallel, and restores data only after validation has passed [6]. An RTO (T2→T6) built by adding the intervals in series can therefore be longer than the actual value when work that can run in parallel does run in parallel. The examples in this guide add the intervals in series.
### Differences in reading during a restore by generation
When you restore from an FSx backup on a first-generation file system, reads of the volume start after all metadata and data are loaded. On a second-generation file system the volume can be read during the restore once it reports `CREATED` (documented, [8]). T5 is the time the quick check matched, regardless of generation. The time of `CREATED` and T5 do not always coincide, so a measurement records them separately.
## Features of each recovery layer and where the measurements are
The prerequisites, constraints, treatment of cost, failure domain, and RPO and RTO guidelines of each layer are in the documents below. This guide does not copy their columns and links to them.
- Hub: [comparison of data protection methods](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/reference/comparison/data-protection-methods.md) (Japanese only)
- Hub: [Can Snapshots alone recover?](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/domains/data-protection/notes/snapshots-are-not-a-recovery-plan.md) (Japanese only)
- Hub: [Can backup copies alone recover?](https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/domains/data-protection/notes/backup-copies-across-regions-and-accounts.md) (Japanese only)
- Cyber: [guide to the logically air-gapped vault](../data-protection/aws-backup-logically-air-gapped-vault.md)

Records of the other layers and of the surrounding measurements, each with its own environment, date and number of runs. This guide does not copy their values.

- Observability: [capability map](<https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations/blob/main/docs/en/cyber-resilience-capability-map.md>) (the restore testing row says an end-to-end restore rehearsal needs assembly) and the [verified recovery point guide](<https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations/blob/main/docs/en/verified-recovery-point-guide.md>) (screening a recovery point with FlexClone, ONTAP 9.17.1P7D1, ap-northeast-1, July 2026)
- Hub: [paths are the failover mechanism](<https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/en/domains/block-storage/notes/paths-are-the-failover-mechanism.md>) is the one Multi-AZ failover measurement found (2026-09-05, ap-northeast-1, second generation, one HA pair, ONTAP 9.18.1P5, one run, triggered by a throughput capacity change from 384 to 768 MBps; the ANA state flipped about 66 seconds after the request, and NVMe/TCP stopped for 423.8 seconds on the default kernel). This project does not measure Multi-AZ failover, because its verification file system is first generation SINGLE_AZ_1
- Hub: [limits](<https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/reference/limits/README.md>) (Japanese only) records the SVM upper limit of 6 at 128 MBps of throughput capacity (measured 2026-08-18, ap-northeast-1)
- Observability: the [SLO definition format](<https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations/blob/main/docs/en/pipeline-slo.md>) that the SLO table below reuses
The table below has three columns per layer: the measured S_restore, which part of the RTO the layer falls in, and the `layer` value of the recovery point record. The last row places configurations that do not depend on ONTAP features in the same columns. No layer is ranked.
| Layer | Measured S_restore and existing records | Which part of the RTO | `layer` value |
|---|---|---|---|
| ONTAP Snapshot (`volume snapshot restore`, `restore-file`, FlexClone) | Snapshot restore was measured four times each at 1 GiB and 50 GiB, and the SHA-256 of every file matched (Tokyo Region, ONTAP 9.18.1P6, first generation SINGLE_AZ_1). FlexClone creation is also measured. At 10 GiB, restore took 2.0 to 3.0 seconds on large files and 168.0 to 170.0 seconds on small files (about 80,000). The values and conditions are in the [M1 section of the measurement results](recovery-measurement-results.md#m1-results-snapshot-restore-and-clone-creation). In the middle of the measurement, on 2026-11-20 (JST), ONTAP went from 9.18.1P6 to 9.19.1P4 automatically and affected four 10 GiB clone creations ([extent of the effect](recovery-measurement-results.md#effect-of-the-ontap-version-change)). This is a real example of the version not being user-selectable [E-058]; when you measure in your own environment, read the version before and after the measurement | S_restore. Verifying a recovery point (screening with FlexClone) is an input to S_decide | `ontap-snapshot` |
| SnapMirror destination | The E2E of create, transfer, break, resync and cleanup within one cluster succeeded on 11 items (`automation/fsxn-ops` of Agentic-Access-Aware-RAG, 2026-05-01, ONTAP 9.17.1P4D3, one run per item). Cross-Region setup and break are recorded in fsxn-lakehouse-integrations (2026-07). <!-- TODO(13.2): add the duration of break and resync between two SVMs in one cluster, and the lag distribution (M5) --> | S_restore (break and switch back). The RPO is set by the lag | `snapmirror-destination` |
| FSx backup | The Hub record is a restore of a 1 GiB volume (about 9.4 MiB of data) in 13 minutes 21 seconds, one measurement (2026-08-28, first generation SINGLE_AZ_1). The Hub note itself says this duration is dominated by a fixed part and is not a basis for an RTO. AWS gives general restore rates of 250 MBps for several concurrent restores of mostly large files and 100 MBps for mostly small files [8]. In this project's measurement (Tokyo, first generation SINGLE_AZ_1, 128 MBps, ONTAP 9.19.1P4, 2026-11-20 and 2026-11-21, n=4 per group, a sample run and not a production estimate), a restore took a median of 353, 368 and 552 seconds for large files at 1, 10 and 50 GiB, and 1023 seconds for 10 GiB of small files (about 80,000). Most of the time is a fixed part until CREATED, and for small files the number of files is thought to matter (`hypothesis`). The table is in [M2 of the recovery measurement results](recovery-measurement-results.md#m2-results-restore-of-fsx-backups). | S_restore. A restore is a background process that uses the unused part of the throughput capacity [8] | `fsx-backup` |
| AWS Backup vault (including restore testing) | Restore testing covers FSx for ONTAP (documented, Cyber guide). AWS Backup infers only part of the FSx metadata, and the target SVM is given as `storageVirtualMachineId` in `RestoreMetadataOverrides` (documented, [12]). <!-- TODO(13.2): add the result of running a restore testing plan (M3) --> | S_restore. The wait for the start window is not included | `aws-backup-vault` |
| AWS Backup logically air-gapped vault | A recovery point in a shared vault was restored into an existing file system in another account, 1 GiB in 1,362 seconds (lab of the S3 Access Points serverless patterns, 2026-10-12, one measurement; the status line of that record says this row is not recorded for the current portal). It goes through sharing across accounts, so it is not used for comparison with other layers. | S_restore (including sharing and restoring in another account) | `aws-backup-lag-vault` |
| Configurations that do not depend on ONTAP features (EBS snapshots with AWS Backup, database replication, S3 versioning) | Not measured by this project | Depends on the configuration | `other` |
The cases each layer suits and its constraints are written below at the same level of detail. The comparisons are in the links above.
- ONTAP Snapshot: suits restoring quickly from an accidental deletion or corruption inside the same volume. The constraints are that the failure domain is the same as the volume, that the number of Snapshots has an upper limit (Hub note), and that `volume snapshot restore` replaces the current writable copy. While a locked Snapshot (Tamperproof Snapshot) remains, ONTAP cannot be reverted to an earlier version [E-057]
- SnapMirror: suits keeping a recovery point on another file system. The constraints are that the transfer is asynchronous so the RPO is set by the transfer interval and the lag, and that a configuration with a separate file system as the destination is not measured by this project. FSx for ONTAP supports only volume-level SnapMirror, and does not support synchronous SnapMirror (including StrictSync) or SVM DR [E-059]. Design on that basis, and do not plan on `snapmirror failover start` being available
- FSx backup: suits long retention and copying to another Region per volume. The constraints are that on first generation the read starts after the restore completes [8], that the restored volume has the same style as the original [8], and that creating a Snapshot, cloning, SnapMirror and backup on a volume being restored are done after the restore completes [8]
- AWS Backup vault: suits putting backup planning, retention and audit in AWS Backup. The constraints are that an FSx for ONTAP backup is not under full AWS Backup management [E-009] and that its restore procedure differs from the FSx one. Restore testing does not cover temporary recovery points [E-017]
- Logically air-gapped vault: suits protecting backups from deletion and restoring from another account. The constraint is that when the file system is encrypted with an AWS managed key, its backups cannot be copied to the vault [E-009]
- Configurations that do not depend on ONTAP features: suit workloads that do not use, or cannot use, ONTAP features. The constraint is that the way to keep a recovery point differs per configuration, so this project's measurements and steps do not apply
The REST form for restoring a Snapshot is `restore_to.*` on `PATCH /api/storage/volumes/{uuid}` in the NetApp REST reference. The form `POST .../snapshots/{uuid}/restore` that the Observability ToolJet workflow uses is not in the `show-rest` list of ONTAP 9.18.1P6, so this project's steps do not use it.
## How to choose a layer
Answering the questions in order narrows the candidate layers. This is not a ranking. It is a flow for matching each layer's suitable cases and constraints to your own conditions.
| Question | Layer the answer points to | Note |
|---|---|---|
| How much data loss (RPO) is acceptable, in minutes? | Scheduled transfer (SnapMirror) or frequent Snapshots for minutes. Backups for hours to days | The RPO of SnapMirror is set by the lag. The distribution of the lag on a 5-minute schedule is in the measurement results<!-- TODO(13.2): link the section after M5 is final --> |
| How far must the failure you defend against reach? | Volume Snapshots for operator error. SnapMirror or backups for a file system failure. A logically air-gapped vault for account compromise | If you assume a compromise, choose on the assumption that the recovery inputs are not to be used until checked (section "Distinguishing cyber recovery from DR") |
| Is the restore granularity a file or a volume? | `restore-file` or a copy from `.snapshot` for a file. A Snapshot restore or a backup for a volume | `restore-file` cannot take a directory (documented) |
| How much data is there? | The larger it is, the longer a backup restore is expected to take. A Snapshot restore is an operation inside the volume, and in the measurements it stayed in seconds against data size | Avoid extrapolating in proportion. Treat data sizes that were not measured as provisional estimates, separately |
| Can you depend on ONTAP features? | If yes, Snapshot, FlexClone and SnapMirror. If not, EBS snapshots with AWS Backup, database replication, or S3 versioning | For other configurations this project's measurements do not apply. Measure again in your environment |
| Do you need to prevent a recovery point from being altered? | A locked Snapshot or a logically air-gapped vault | A lock comes with operations that cannot be undone and with periods that cannot be released. Estimate the cost and the period in advance |
> **Cost note**: Cost per layer is given as an amount only where the unit price and its assumptions can be written. This guide gives no amounts. Unit prices change by Region and over time, so check the Pricing API on the day.
## Steps for setting SLIs and SLOs
There are eight steps. The service owner decides the values; this project provides inputs and formats.
1. Classify the service and its data. Decide the priority classes for recovery.
2. Choose the start and end of the RTO. The reference definition is RTO (T2→T6), with S_decide shown alongside.
3. Choose the recovery layers. Use the flow in the previous section and the Hub and Cyber comparisons.
4. Measure the intervals in your own environment. Follow the next subsection.
5. Decide the RTO and RPO values. Use the measured range as input; the size of the margin is the service owner's decision.
6. Build the SLI and SLO tables. Use the table of six SLIs below and the four-column format.
7. Plan restore drills and restore tests (section "Running restore drills and restore tests").
8. Review in the PDCA cycle (section "When to revisit the objectives in the PDCA cycle").
The SLO table reuses the Observability [SLO definition format](https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations/blob/main/management-console/README.md) (four columns: SLI, SLO target, measurement, error budget over 30 days). The description that uses burn-rate windows is in the Observability [pipeline SLO](https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations/blob/main/docs/en/pipeline-slo.md). It is for high-frequency events and does not apply to restore tests.
The candidate SLIs are the six below.
| SLI | How to measure | Data source | Frequency | Minimum sample count | Known pitfalls |
|---|---|---|---|---|---|
| Recovery point freshness (i) | Time elapsed since the creation of the latest recovery point (one that exists) | Creation time of the ONTAP Snapshot, `describe-backups`, AWS Backup recovery points | 5 minutes to 1 hour | Continuous value, no sample-count constraint | The time basis can differ per source. Tell a failed fetch from a worsening freshness |
| Recovery point freshness (ii) | Time elapsed since the latest verified recovery point | The Observability ledger (the latest `started_at` with `verdict: clean`). Write "not obtained" when there is no ledger | At each verification | Same as above | Verification is a pre-filter and not a forensic finding. `clean` is not a sufficient condition for recovery |
| SnapMirror lag | Lag and state per relationship | `lag_time` of the ONTAP REST API (an ISO 8601 duration), the Observability `FSxONTAP/SnapMirror` metric | 5 minutes | Continuous value | One observation returned `healthy: true` for an `uninitialized` relationship (Observability, 2026-10-08, ONTAP 9.18.1P6). Do not use `healthy` alone as an SLI; use state and lag together. Whether the CloudWatch `AWS/FSx` namespace has a metric dedicated to SnapMirror lag has not been confirmed<!-- TODO(13.2): add the result of `list-metrics` from M6 --> |
| Recovery success rate | Share of restore tests that succeed. Successes ÷ (successes + failures) | `aws backup list-restore-jobs --by-restore-testing-plan-arn`. The states are PENDING, RUNNING, COMPLETED, ABORTED and FAILED; no value corresponds to `COMPLETED_WITH_ISSUES` [10] | Per test | State the number of tests N in the window and the tolerated failures floor(N × (1 − SLO)) | Temporary recovery points are outside restore testing [E-017]. The CloudWatch `NumberOfRestoreJobsCompleted` and `NumberOfRestoreJobsFailed` also count restores done in operations, so use them only for trends [11]. Decide whether to include data-consistency checks in success |
| Restore duration | S_restore | Creation and completion times of the restore job | Per test | Write p50 only with 5 or more samples and p95 only with 20 or more. Otherwise write the maximum and the count | Depends on data size and file shape. Do not include the wait for the start window |
| Backup job success rate | Successes ÷ (successes + failures + completed with issues) | Counts by state from `aws backup list-backup-jobs`. Success is `State=COMPLETED` with `MessageCategory=SUCCESS`, failure is `State=FAILED`, and completed with issues is the count of `State=COMPLETED` minus the success count [9] | Daily | Number of jobs in the window | `Completed with issues` is a state of the AWS Backup console only and cannot be tracked in CloudWatch [11]. With an AWS managed key it arises when copying to a logically air-gapped vault [E-009]. The API returns only the last 30 days [9]. For a window longer than 30 days, store and count the `Backup Job State Change` events of EventBridge. Whether the CloudWatch `NumberOfBackupJobsCompleted` includes jobs completed with issues is not stated in the documentation<!-- TODO(13.2): add from M6 the real-environment behaviour of `BackupCompletedWithIssues` in the template and the cross-check of counts from two fetches of list-backup-jobs --> |
Whether to count `EXPIRED`, `ABORTED` and `PARTIAL` in the denominator is the service owner's decision. When you use only the `AWS/Backup` metrics of CloudWatch, write "share of completed jobs" and do not write success rate. The Observability `FsxOntap/Backup` holds only the count of failures and has no denominator.
The AWS Resilience Hub list of supported resources does not name FSx for ONTAP, and a resource not on the list is described as not fully supported [E-051]. RTO and RPO are therefore evaluated in a separate measurement system: the scripts in this guide and AWS Backup restore testing. When you quote an AWS whitepaper or a Resilience Hub default, add its URL and say it is a general example and not a norm.
Define the error budget as the complement of the SLO for events that have 20 or more samples in the evaluation window (backup jobs, lag and so on). What to do when the budget is used up (for example, stopping new changes to work on reliability) is the service owner's decision.
### Measuring the intervals in your own environment
Measured values differ from the service owner's data size, file count, file size, throughput capacity and generation. The steps for measuring again in your environment are below.
1. Follow the working rules in the README of the measurement scripts (`benchmarks/recovery/README.md`, not yet on the main branch). Show the operations to execute in a dry-run first, and execute only the operations that were shown.
2. Create only resources that carry the name prefix and the tags. Run destructive operations only on resources whose identifiers match the list of resources to tear down.
3. Before measuring, check the free SSD capacity, the background load and the expected cost. Get the cost from the Pricing API.
4. Measure the same configuration in series at least three times and write the minimum, median and maximum. To compare two configurations, measure at least four runs each, alternately.
5. Export what teardown destroys first, and after teardown confirm twice that the resources are not found.
### Where freshness comes from and which clock it uses
The time basis of recovery point freshness can differ per source. Write the source in the SLI definition.
| Recovery layer | Source | Time basis |
|---|---|---|
| ONTAP Snapshot | `create_time` in ONTAP | ONTAP cluster time |
| SnapMirror | `lag_time` (an ISO 8601 duration) | Elapsed since the start of the transfer. It forms a sawtooth |
| FSx backup | Creation time in `describe-backups` | FSx service time |
| AWS Backup | Creation time of the recovery point | AWS Backup service time |
### Handling infrequent events
For an SLI whose events number fewer than 20 in the evaluation window, such as restore tests and drills, do not use p95 or an error budget. With four samples, p95 equals the maximum. When `N × (1 − SLO)` is below 1, one failure uses up the window's budget, and the action for a used-up budget fires every time. Write infrequent events in two ways.
1. Pass or fail per event. Write per run whether the value met the target (for example, S_restore at or below the target).
2. Count within the window. Write failures ÷ the number of tests N. When `N × (1 − SLO) < 1`, write "one failure misses the SLO", and let the service owner decide whether to lengthen the window (for example to a quarter) or to raise the test frequency.
Write p50 only with 5 or more samples and p95 only with 20 or more. With fewer, write the maximum and the count (do not call it p95).
## Example numbers built by arithmetic
> **About the examples**: Every number in this section is an example. It is a promise to no end user and not a recommended value. A value built from a measurement by arithmetic carries its formula, and intervals that were not measured are written as arbitrary assumptions in separate cells.
The table below builds examples of RTO (T2→T6) and RTO (T3→T6) from a sum of intervals. The S_restore value is a measurement and the rest are arbitrary assumptions.
| Interval or RTO | Example value (seconds) | Source |
|---|---|---|
| S_decide | 1,800 | Arbitrary assumption |
| S_prepare | 300 | Arbitrary assumption |
| S_restore | 15 | Measurement (Snapshot restore, 50 GiB of large files, maximum of four runs, Tokyo Region, ONTAP 9.18.1P6, first generation SINGLE_AZ_1, 2026-11-18). The interval crosses two clocks and its error is about 2 seconds. Treat it only as a guide to an upper bound, not as a table value. <!-- TODO(13.2): replace this row with the final aggregate and the resolution verdict --> |
| S_accept | 600 | Arbitrary assumption |
| RTO (T2→T6) | 2,715 | Formula: 1,800 + 300 + 15 + 600 |
| RTO (T3→T6) | 915 | Formula: 300 + 15 + 600 |
The table below gives example SLOs. The four-column format is Observability's.
| SLI | SLO target (example) | How to measure | Error budget (30 days) |
|---|---|---|---|
| Recovery point freshness (i) | 99% of the time the age of the latest recovery point is 60 minutes or less (arbitrary assumption) | Computed every 5 minutes from the creation time of the Snapshot | 43,200 minutes × 1% = 432 minutes |
| Backup job success rate | 95% (arbitrary assumption) | One daily job over 30 days, 30 in all. Successes ÷ (successes + failures + completed with issues) | 30 jobs × 5% = 1.5 jobs. Up to 1 failure or issue |
| Recovery success rate | 0 failures in 4 restore tests per quarter (arbitrary assumption) | Restore jobs of the restore tests | 4 × (1 − SLO) is below 1, so no budget is used and one failure misses the target |
| Restore duration (S_restore) | 600 seconds or less per run (arbitrary assumption. The measured maximum of 15 seconds is for a Snapshot restore and is not a value for other layers) | Creation and completion times of the restore job per test | Pass or fail per run. Fewer than 5 samples, so write the maximum and the count |
## Running restore drills and restore tests
The purpose of a restore drill is not to show that a backup exists. It is to confirm that the restored data is usable and falls within the RTO and RPO. REL09-BP04 of the AWS Well-Architected Framework asks you to query the restored data to confirm it is usable, not to assume a restore works because a backup exists, and to use a runbook or an automated procedure [5].
Confirm the following in each drill.
1. The restored data reads without corruption or loss. Write it as two stages: a quick check that hashes parts of the files, and a check of every file.
2. The acceptance conditions (for example the application response) are met. This is up to T6.
3. S_restore and the time from T2 to T6 fall within the service owner's objectives.
4. The data loss falls within the RPO.
A starting point for frequency and owner is the DR test table of the Cyber [ransomware recovery runbook](../runbooks/ransomware-recovery.md). The service owner decides the frequency. AWS Backup restore testing creates a plan, restores and validates automatically, and deletes the restored volume after the validation window. The specification of restore testing for FSx for ONTAP is in the Cyber [guide to the logically air-gapped vault](../data-protection/aws-backup-logically-air-gapped-vault.md), and this project's own measurement will be added to the measurement results once <!-- TODO(13.2): link the section of the M3 result -->it is final. A practitioner resource on restore drills is [7].
## Distinguishing cyber recovery from DR
Cyber recovery is recovery to a known-good state when the recovery inputs themselves, such as backups, credentials and infrastructure, may have been compromised [6]. DR broadly means recovering from a failure. What this distinction looks at is not using the recovery inputs and the recovery environment until they have been checked. The AWS reference approach lists these points [6].
- The recovery environment does not share a trust boundary (accounts, keys and network paths) with the environment being recovered. Recovery work is not done in the production account that is suspected of compromise
- The recovery point is not the latest one but the newest one that predates the boundary of the event and passed validation. If validation fails, step back to the previous candidate
- Validation separates having restored (the data reads) from being safe to use. It combines a malware scan, workload-specific checks such as database consistency, and a log review
- Infrastructure is rebuilt from code, data is restored from backup, and credentials are issued anew and not restored
- Investigation, validation and the infrastructure rebuild run in parallel, and only validated data is restored
- Preparing for the loss of an entire Region is a separate concern from protection against deletion. Replication alone does not protect against corruption or destruction of data; a way to return to a point in time is needed [3]
In the intervals of this guide, S_decide (the time to decide the recovery point) tends to be longer in cyber recovery (interpretation). Keep the decision record on the recovery point in the format of the next section.
## Hand-over format to the third pillar
The third pillar (forensics) decides the recovery point, records the decision and hands it to the second pillar. The second pillar writes a restore record that refers to it. The direction follows the programme document. The second pillar, which starts first, defines the format, and the machine-readable schema is [`docs/agent/recovery-point-record.schema.json`](../agent/recovery-point-record.schema.json). The schema is the authority on the list of fields, and the table below summarizes them by who fills them. A service owner that has no third-pillar procedure and writes the decision by hand still writes it as a decision record.
| Group | Fields | Filled by | Content |
|---|---|---|---|
| Common | `schema_version`, `record_id`, `service`, `incident_ref`, `authored_by`, `clock_source`, `integrity` | Both | The same `service` and `incident_ref` tie the two records. `incident_ref` is an identifier the service owner assigns and holds no support case number |
| Times of the decision record (`authored_by: pillar3`) | `decision_started_at`, `decided_at` (T3), `decided_by_role` | Third pillar | The time the decision took. Write a role name and no personal name |
| Content of the decision record | `candidates`, `chosen`, `suspected_compromise_window`, `evidence_refs`, `preservation` | Third pillar | The candidates, the choice and its rationale, the data loss accepted, the suspected compromise period, references to evidence, and preservation for investigation |
| Declaration in the restore record (`authored_by: pillar2`) | `declared_at` (T2), `decision_ref` | Second pillar | The recovery declaration and the reference to the decision record |
| Content of the restore record | `restore.started_at` (T4), `restore.data_available_at` (T5), `restore.accepted_at` (T6), `restore.completed_at`, `restore.job_id`, `restore.cutover_at` (T7, optional) | Second pillar | The method and target of the restore and the times of the operation. `completed_at` is the end of the restore operation and differs from T5 |
| Candidate layer and verdict | `candidates[].layer`, `candidates[].integrity_checks[].result` | Third pillar | `layer` is the recovery layer and not an evidence tier. `result` is `clean`, `suspicious` or `error` (the verdict words of the Observability ledger). A FlexClone verdict is a pre-filter, and `clean` is not a sufficient condition for recovery |
The columns that the recovery point list of the file portal (S3 Access Points serverless patterns) shows (creation time, state, resource type, size, encryption, vault name and the logically air-gapped vault indicator) are part of where the candidate fields come from. The portal handles presenting recovery points and restoring with approval, and writing a recovery point record would be a future addition that is that repository's decision ([recovery point and restore design](https://github.com/Yoshiki0705/FSx-for-ONTAP-S3AccessPoints-Serverless-Patterns/blob/main/solutions/amplify-portal/docs/data-protection-recovery-design.md)).
How to handle the records is as follows.
- A record, once written, is not rewritten. A correction is a new record whose `integrity.supersedes` names the record it replaces. One record can be replaced by only one record
- Write times in ISO 8601 in UTC and put the time source in `clock_source`. Matching the times of ONTAP audit logs, EMS, CloudTrail and Snapshots with each other is an `open` item of the third pillar, and the schema only provides the field that records the time source
- `integrity.record_sha256` is the SHA-256 of the record without `integrity`, serialised as JSON with keys sorted, no extra whitespace, and UTF-8. It shows the internal consistency of the record and not the authenticity of its writer. There is one chain per pair of `service` and `incident_ref`, and every record except the first sets `prev_record_sha256` to the hash of the record before it
- Where the records are stored (append-only storage, or copying the hash to a separate system) is the service owner's decision. Signing is an `open` item of the third pillar
- When `chosen.rationale_codes` includes `before-compromise-window`, `suspected_compromise_window` is required
### Calculations from the two records
Tying the two records with `decision_ref` lets you compute the two RTO values and S_decide.
1. S_decide = `decided_at` of the decision record − `declared_at` of the restore record. `decision_started_at` is used to split S_decide into the wait from the declaration to the start and the deliberation from the start to the decision, and is not used in the definition
2. RTO (T2→T6) = `restore.accepted_at` − `declared_at`
3. RTO (T3→T6) = `restore.accepted_at` − `decided_at`
4. S_restore = `restore.data_available_at` − `restore.started_at`. When the interval crosses clocks, write the error following the rule of the measurement record
### Record example
The example below has the same values as the arithmetic example in the previous section. Every value is arbitrary and refers to no real resource, account or person. The two complete records are `valid-decision.json` and `valid-restore.json` in `tests/fixtures/recovery/recovery_point_record/`.
```json
{
  "record_id": "rpr-20261201-decision",
  "service": "example-file-service",
  "incident_ref": "inc-example-0001",
  "authored_by": "pillar3",
  "decision_started_at": "2026-12-01T02:10:00Z",
  "decided_at": "2026-12-01T02:30:00Z",
  "chosen": {
    "recovery_point_id": "<snapshot-2100>",
    "rationale_codes": ["latest-clean", "before-compromise-window"],
    "accepted_data_loss_seconds": 18000
  }
}
```
```json
{
  "record_id": "rpr-20261201-restore",
  "service": "example-file-service",
  "incident_ref": "inc-example-0001",
  "authored_by": "pillar2",
  "declared_at": "2026-12-01T02:00:00Z",
  "decision_ref": "rpr-20261201-decision",
  "restore": {
    "started_at": "2026-12-01T02:35:00Z",
    "data_available_at": "2026-12-01T02:35:15Z",
    "accepted_at": "2026-12-01T02:45:15Z"
  }
}
```
In this example S_decide is 1,800 seconds (02:30:00 − 02:00:00), RTO (T2→T6) is 2,715 seconds and RTO (T3→T6) is 915 seconds. The two excerpts above omit some required fields and so do not pass schema validation. The complete records that pass are in the files named above.
## When to revisit the objectives in the PDCA cycle
The mapping between the four PDCA stages and the Resilience lifecycle is in the programme document under [The PDCA cycle](cyber-resilience-programme.md#the-pdca-cycle). The column of the second pillar is filled with links to this guide. The table below gives examples of triggers that start a review.
| Trigger | What to review | Reference to the steps |
|---|---|---|
| The ONTAP version changed, or the throughput capacity or SSD capacity changed | The measured S_restore and the SLO targets | Run "Measuring the intervals in your own environment" again |
| The data size or the file shape changed substantially | S_restore and the numbers in the RTO example | Same as above. Treat estimates for data sizes that were not measured as provisional |
| A restore drill missed the objective | The RTO and RPO values, the choice of layers, the runbook | Return to "How to choose a layer" |
| There was a period in which the SLO was not met | The target values, how to measure, how the error budget is handled | Steps 5 and 6 |
| The configuration of recovery layers changed (for example a vault was added) | The candidate layers, the `layer` values, the sources | Steps 3 and 4 |
The way of thinking about the metrics that review results is in OPS09-BP01 [4].
## References
Numbers correspond to `[n]` in the text. `[E-nnn]` is the number of a "cannot" claim registered in [evidence-ledger.json](../agent/evidence-ledger.json). For dates, the publication date is the one shown on the page and the reference date is the day the content of the URL was checked. Titles are the original titles given by the publisher.
| No. | Title | Publisher | Publication date or version | URL | Reference date | Evidence tier |
|---|---|---|---|---|---|---|
| 1 | Resilience lifecycle framework: A continuous approach to resilience improvement | AWS Prescriptive Guidance | 2023-10-06 (first edition) | [docs.aws.amazon.com](https://docs.aws.amazon.com/prescriptive-guidance/latest/resilience-lifecycle-framework/introduction.html) | 2026-11-12 | documented |
| 2 | REL13-BP01 Define recovery objectives for downtime and data loss | AWS Well-Architected Framework | Versioned path 2025-02-25 | [docs.aws.amazon.com](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/rel_planning_for_recovery_objective_defined_recovery.html) | 2026-11-13 | documented |
| 3 | REL13-BP02 Use defined recovery strategies to meet the recovery objectives | AWS Well-Architected Framework | Versioned path 2025-02-25 | [docs.aws.amazon.com](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/rel_planning_for_recovery_disaster_recovery.html) | 2026-11-13 | documented |
| 4 | OPS09-BP01 Measure operations goals and KPIs with metrics | AWS Well-Architected Framework | Versioned path 2025-02-25 | [docs.aws.amazon.com](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/ops_operations_health_measure_ops_goals_kpis.html) | 2026-11-13 | documented |
| 5 | REL09-BP04 Perform periodic recovery of the data to verify backup integrity and processes | AWS Well-Architected Framework | Versioned path 2025-02-25. The top of the page states it is for historical reference | [docs.aws.amazon.com](https://docs.aws.amazon.com/wellarchitected/2025-02-25/framework/rel_backing_up_data_periodic_recovery_testing_data.html) | 2026-11-19 | documented |
| 6 | Cyber recovery on AWS: A reference approach for recovering from ransomware and destructive events | AWS Architecture Blog | Published 2026-05-20, updated 2026-10-22 | [aws.amazon.com](https://aws.amazon.com/blogs/architecture/cyber-resilience-on-aws-a-reference-approach-for-recovery-from-ransomware-and-destructive-events/) | 2026-11-19 | documented |
| 7 | Planning a NIST-aligned ransomware recovery strategy on AWS, Building isolated, immutable backups for ransomware recovery on AWS, Test backups and restore critical workloads after ransomware on AWS | AWS (AWS re:Post, a three-part series by AWS Support) | 2026-10-15 | [Part 1](https://repost.aws/articles/ARatcO81HOTyCDYQbX5h30pg/planning-a-nist-aligned-ransomware-recovery-strategy-on-aws), [Part 2](https://repost.aws/articles/AR9O5kMiZdRL2CBrdXqUI38g/building-isolated-immutable-backups-for-ransomware-recovery-on-aws), [Part 3](https://repost.aws/articles/ARU6N19cQrQi66Oj-RiasMPQ/test-backups-and-restore-critical-workloads-after-ransomware-on-aws) | 2026-11-12 | documented (the same as reference 27 of the programme document. This guide points to it as a general resource and quotes no individual statement) |
| 8 | Protecting your data with backups (Amazon FSx for NetApp ONTAP User Guide) | AWS | No date shown | [docs.aws.amazon.com](https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/using-backups.html) | 2026-11-19 | documented |
| 9 | ListBackupJobs (AWS Backup API Reference) | AWS | No date shown | [docs.aws.amazon.com](https://docs.aws.amazon.com/aws-backup/latest/APIReference/API_ListBackupJobs.html) | 2026-11-19 | documented (the last 30 days, and the existence of `ByMessageCategory`). The formula for the count completed with issues from combinations of states is this project's reading of the AWS Backup documentation, and has not been cross-checked in a real environment |
| 10 | ListRestoreJobs (AWS Backup API Reference) | AWS | No date shown | [docs.aws.amazon.com](https://docs.aws.amazon.com/aws-backup/latest/APIReference/API_ListRestoreJobs.html) | 2026-11-19 | documented |
| 11 | Monitoring AWS Backup with Amazon CloudWatch (AWS Backup Developer Guide) | AWS | No date shown | [docs.aws.amazon.com](https://docs.aws.amazon.com/aws-backup/latest/devguide/cloudwatch.html) | 2026-11-19 | documented |
| 12 | Restore testing inferred metadata (AWS Backup Developer Guide) | AWS | No date shown | [docs.aws.amazon.com](https://docs.aws.amazon.com/aws-backup/latest/devguide/restore-testing-inferred-metadata.html) | 2026-11-19 | documented |
The source of [E-051] is the AWS Resilience Hub [list of supported resources](https://docs.aws.amazon.com/resilience-hub/latest/userguide/supported-resources.html) (2026-11-13, documented). This guide writes no vendor SLA figure.

# Snapshot restore and clone creation took seconds on large files and about 3 minutes on 10 GiB of about 80,000 files (one file system, 4 runs each)
> **Summary**: This document gives the time of Snapshot restore (`volume snapshot restore`, `restore-file`) and clone creation (FlexClone) measured on one verification file system in the Tokyo Region. The restore of FSx backups (M2) is also included. The measurements of AWS Backup, clean rebuild and SnapMirror are in progress or not started, and carry no numbers. The values are a sample run, not a production estimate. Usage and definitions are in the [guide to recovery time and recovery point objectives](recovery-objectives-guide.md).
## Conclusions
- What was measured: Snapshot restore and clone creation, 4 runs each, at 1, 10 and 50 GiB of large files and at 10 GiB of about 80,000 small files.
- On large files, restore took 1.0 to 15.0 seconds and clone creation 1.0 to 6.0 seconds. At 10 GiB in the small-file shape, restore took 168.0 to 170.0 seconds and clone creation 175.0 to 202.0 seconds.
- At the same 10 GiB, the ranges of the two file shapes do not overlap ([differences by data size and file shape](#differences-by-data-size-and-file-shape)).
- This is a sample run on one file system, repeating one configuration. It is not a production estimate and not a value for other configurations.
- During the measurement, ONTAP on the file system went from 9.18.1P6 to 9.19.1P4. Four of the 10 GiB clone creations are affected ([effect of the ONTAP version change](#effect-of-the-ontap-version-change)).
- The restore of FSx backups (M2) is in the section below. AWS Backup (M3) has interim numbers (in progress, n=1). Clean rebuild (M4), SnapMirror (M5) and CloudWatch metrics (M6) have no numbers.
## Measurement conditions
The following conditions are common to every M1 measurement.
| Item | Value |
|---|---|
| Region | ap-northeast-1 |
| File system | FSx for ONTAP first generation, SINGLE_AZ_1, throughput capacity 128 MBps, one file system |
| ONTAP version | 9.18.1P6. Updated to 9.19.1P4 in the weekly maintenance of 2026-11-19 16:19Z to 16:46Z (2026-11-20 01:19 to 01:46 JST) (below). The version is not user-selectable [E-058] |
| Client | EC2 c7gn.large |
| Operation route | ONTAP REST PATCH (`route=rest-patch`). The client was remounted before each run (`cache=remount`) |
| Measurement dates | 2026-11-18 and 2026-11-19 (UTC) |
| Runs | 4 per group, repeated in series with the same configuration |
| Time resolution | 1 second. The error of a subtraction across clocks is about 2 seconds (about 5 seconds for `snapshot-dir-copy`) |
The ONTAP version change, in time order.
| Time (UTC) | Event |
|---|---|
| 2026-11-19 16:19Z | Failover of node -02 |
| 2026-11-19 16:31Z | Giveback of node -01 |
| 2026-11-19 16:34Z | Failover of node -01 |
| 2026-11-19 16:46Z | Giveback of node -02 (the last recorded event) |
`environment.ontap_version` in a record is the version read when the measurement started, copied into the record. It was not read per record. For that reason four 10 GiB clone creations still say 9.18.1P6 in their records but were in fact measured during or after the update. The correction is kept in a separate record, and the original records are not edited. All other groups (including the 8 restores) were measured before the update.
## Relation to earlier records
The earlier records of other layers (FSx backups, the AWS Backup logically air-gapped vault, SnapMirror) are in the table of [features of each recovery layer and where the measurements are](recovery-objectives-guide.md#features-of-each-recovery-layer-and-where-the-measurements-are) in the guide. Each record has its own environment and number of runs, and is not compared side by side with the values in this document. When the measurements from M2 onward finish, this section gets the correspondence.

The records below are the ones each measurement builds on. Each line says what the record measured; their values are not copied here.

- M2 (restore of FSx backups): the Hub note on [backup copies across Regions and accounts](<https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/ja/domains/data-protection/notes/backup-copies-across-regions-and-accounts.md>) (Japanese only) records the copy and restore of a 9.4 MiB data set, first generation SINGLE_AZ_1, AWS managed key, 2026-08-28 and 2026-08-29, one run per step. The [shared-vault lab record](<https://github.com/Yoshiki0705/FSx-for-ONTAP-S3AccessPoints-Serverless-Patterns/blob/main/infrastructure/shared-backup-vault-lab/docs/verification-record.en.md>) records a logically air-gapped vault shared between two accounts, 2026-10-12, one run per item (its status line lists which rows hold for the current portal); its [CloudFormation template](<https://github.com/Yoshiki0705/FSx-for-ONTAP-S3AccessPoints-Serverless-Patterns/blob/main/infrastructure/shared-backup-vault-lab/cloudformation/owner-base.yaml>) creates a file system with a customer managed key, and this project reuses that approach instead of writing a new one
- M2 (read-back after a restore): the S3-Burst-on-ONTAP-Files [performance testing guide](<https://github.com/Yoshiki0705/S3-Burst-on-ONTAP-Files/blob/main/docs/en/reference/performance-testing-guide.md>) lists, among the items it hit, that a 280 GiB data set (18% over the 256 GB in-memory tier) still had 98.5% to 99.9% of its reads not going to disk. Remounting the client does not clear storage-side memory, so a read-back time right after a restore may include a cache effect (an inference, not measured here)
- M4 (clean rebuild): [verification of ATX containerization on FSx for ONTAP storage](<https://github.com/Yoshiki0705/FSx-for-ONTAP-Container-Datastore-Patterns/blob/main/docs/en/atx-containerization-fsxn-storage-verification.md>), section 3.3, hands-on results for configuration 1 (a compute replacement that keeps the data in place): 2026-11-10, ap-northeast-1, a disposable SVM and a 1 GiB volume, one observation per item
- M5 (SnapMirror): the [verification report of `automation/fsxn-ops`](<https://github.com/Yoshiki0705/FSx-for-ONTAP-Agentic-Access-Aware-RAG/blob/main/automation/fsxn-ops/docs/aws-verification-report.md>) (create, transfer, break, resync and cleanup within one cluster, ONTAP 9.17.1P4D3, 2026-05-01, 11 of 11 tests passed, no durations); the Observability [custom-metrics module run](<https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations/blob/main/docs/en/verification-results-cloudwatch-monitoring.md#terraform-custom-metrics-module-run-on-2026-10-08>) (lag and health between two volumes of one SVM, ONTAP 9.18.1P6, 2026-10-08, one run, first lag value 22 seconds); the [cross-Region SnapMirror findings](<https://github.com/Yoshiki0705/FSx-for-ONTAP-Lakehouse-Integrations/blob/main/integrations/snapmirror-flexcache-multicloud/docs/en/research.md>) (SM-VAL-008 to 011: ap-northeast-1 to us-west-2, about 3 minutes from break to S3 Access Points re-attach, 2026-07-22, one run); the portal [verification results](<https://github.com/Yoshiki0705/FSx-for-ONTAP-S3AccessPoints-Serverless-Patterns/blob/main/solutions/amplify-portal/docs/verification-results.en.md>) (SnapMirror create, delete, quiesce, resume and update, ONTAP 9.18.1P3D1, 2026-08-14 and 2026-08-15, no break or resync; the [pitfalls note](<https://github.com/Yoshiki0705/FSx-for-ONTAP-S3AccessPoints-Serverless-Patterns/blob/main/docs/agent/pitfalls-flexcache-snapmirror.md>) lists the create and delete pitfalls of the same portal run)
- M6 (CloudWatch metrics): Observability [`aws-backup-events.yaml`](<https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations/blob/main/shared/templates/aws-backup-events.yaml>) (backup job events) and the [monitoring design](<https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations/blob/main/docs/en/monitoring-design.md>), which records that no native SnapMirror relationship metric appeared on the AWS metric pages read on 2026-10-07
- Multi-AZ failover is not measured in this project. The one record is the Hub note [paths are the failover mechanism](<https://github.com/Yoshiki0705/FSx-for-ONTAP-Adoption-Playbook/blob/main/docs/en/domains/block-storage/notes/paths-are-the-failover-mechanism.md>) (2026-09-05, second generation, one HA pair, one run, block protocols)
## M1 results: Snapshot restore and clone creation
Unit: seconds. n is the number of usable successful records. The range is the minimum and the maximum, not a confidence interval. Data size is in GiB. The number of attempts and of excluded records is added once the aggregate is final.
| Measurement | Data size (GiB) | File shape | n | Median | Min–max | ONTAP version | Date (UTC) |
|---|---|---|---|---|---|---|---|
| Restore (`volume-snapshot-restore`) | 1 | Large files | 4 | 2.0 | 1.0–2.0 | 9.18.1P6 | 2026-11-18 |
| Restore (`volume-snapshot-restore`) | 10 | Large files | 4 | 2.5 | 2.0–3.0 | 9.18.1P6 | 2026-11-18 to 2026-11-19 |
| Restore (`volume-snapshot-restore`) | 10 | Small files | 4 | 168.5 | 168.0–170.0 | 9.18.1P6 | 2026-11-19 |
| Restore (`volume-snapshot-restore`) | 50 | Large files | 4 | 7.0 | 7.0–15.0 | 9.18.1P6 | 2026-11-18 |
| File restore (`restore-file`) | 1 | Large files | 4 | 1.0 | 1.0–2.0 | 9.18.1P6 | 2026-11-18 |
| Copy from `.snapshot` (`snapshot-dir-copy`) | 1 | Large files | 4 | 7.299 | 6.862–7.461 | 9.18.1P6 | 2026-11-18 |
| Clone creation (`flexclone-create`) | 1 | Large files | 4 | 1.5 | 1.0–2.0 | 9.18.1P6 | 2026-11-18 |
| Clone creation (`flexclone-create`) | 10 | Large files | 4 | 2.5 | 2.0–4.0 | Runs 1 and 2 on 9.18.1P6, run 3 during the update, run 4 on 9.19.1P4 (estimated) | 2026-11-19 |
| Clone creation (`flexclone-create`) | 10 | Small files | 4 | 193.0 | 175.0–202.0 | Runs 1 and 2 on 9.18.1P6, runs 3 and 4 on 9.19.1P4 (estimated) | 2026-11-19 |
| Clone creation (`flexclone-create`) | 50 | Large files | 4 | 4.0 | 4.0–6.0 | 9.18.1P6 | 2026-11-18 |
"9.19.1P4 (estimated)" is a version inferred from the run having started after the update finished, not a value read per record. For `volume-snapshot-restore` at 1 GiB and 50 GiB, the SHA-256 of every file matched the manifest.
The time resolution is 1 second, and the error of a subtraction across clocks is about 2 seconds (about 5 seconds for `snapshot-dir-copy`). A difference of about 1 second, such as 2.0 and 2.5 seconds, is within the resolution. The 50 GiB restore maximum of 15.0 seconds occurred on the first run only; runs 2 to 4 took 7.0 seconds.
### Differences by data size and file shape
The two shapes at 10 GiB, compared (same configuration, 4 runs each).
| Measurement | Range on large files (s) | Range on small files (s) | Overlap of ranges |
|---|---|---|---|
| Restore (`volume-snapshot-restore`) | 2.0–3.0 | 168.0–170.0 | None. The difference is about 166 seconds |
| Clone creation (`flexclone-create`) | 2.0–4.0 | 175.0–202.0 | None. The difference is larger than the width of the small-file range (27 seconds) |
What was observed is that at the same 10 GiB, the small-file shape took about 70 times as long for restore (medians 168.5 and 2.5 seconds) and about 80 times as long for clone creation (193.0 and 2.5 seconds). The cause is a `hypothesis`: the amount of metadata that about 80,000 files create is suspected to have lengthened the time, but no experiment changed the number of files alone.
On large files at 1, 10 and 50 GiB, the restore medians were 2.0, 2.5 and 7.0 seconds and the clone creation medians 1.5, 2.5 and 4.0 seconds. The values tend to grow with the data size, but part of each difference is within the 1-second resolution. No other data size is extrapolated from these three points.
### Effect of the ONTAP version change
The two 10 GiB clone creation groups each have two runs on each side of the change. The values are as follows (seconds).
| Group | 9.18.1P6 (runs 1 and 2) | During the update and 9.19.1P4 (estimated) | Range of the group |
|---|---|---|---|
| Large files | 3, 2 | 4 (during the update), 2 (9.19.1P4, estimated) | 2.0–4.0 |
| Small files | 191, 195 | 202, 175 (both 9.19.1P4, estimated) | 175.0–202.0 |
With n=2 on each version, the effect of the version cannot be separated. In both groups, the values after the update lie inside the group range that includes the values before it. The maintainer decided not to remeasure with 4 runs each on 9.19.1P4. Read the values in the table with the version note.
This update is a real example of the version not being user-selectable [E-058]. The only thing a user sets on a file system is the start time of the weekly maintenance window, and the version can change in the middle of a measurement.
## M2 results: restore of FSx backups
Measured on one file system in Tokyo (ap-northeast-1; first generation SINGLE_AZ_1, 128 MBps, ONTAP 9.19.1P4 in all 32 records) on 2026-11-20 and 2026-11-21 (the date basis has not been confirmed to be the same as in the M1 table). The driver ran on an EC2 instance in the VPC (t4g.small) and the client was a c7gn.large. The client was stopped during a restore, and that interval is not part of the time. Unit: seconds. n is the number of usable successful records, 4 in each group. The range is the minimum and the maximum, not a confidence interval. The values are a sample run on one file system, not a production estimate.
| Measurement | Data size (GiB) | File shape | n | Median | Min–max | Median to CREATED |
|---|---|---|---|---|---|---|
| Backup creation | 1 | Large files | 4 | 192 | 162–242 | none |
| Backup creation | 10 | Large files | 4 | 272 | 222–312 | none |
| Backup creation | 10 | Small files | 4 | 247 | 212–272 | none |
| Backup creation | 50 | Large files | 4 | 388 | 353–463 | none |
| Restore from backup | 1 | Large files | 4 | 353 | 344–354 | 352 |
| Restore from backup | 10 | Large files | 4 | 368 | 354–374 | 368 |
| Restore from backup | 10 | Small files | 4 | 1023 | 1004–1056 | 860 |
| Restore from backup | 50 | Large files | 4 | 552 | 537–577 | 549 |
- The restore time is the sum of the time from the restore call until CREATED is seen and the time from mount to the quick check. CREATED is detected by reading every 10 seconds, so the resolution is 10 seconds.
- For large files from 1 to 50 GiB, most of the time is a fixed part of about 350 seconds until CREATED. With 50 times the data, the restore took about 1.6 times as long (353 and 552 seconds). For the same 10 GiB, about 80,000 small files took about 2.8 times as long as large files (1023 and 368 seconds). The reason is a `hypothesis`: the amount of metadata that the number of files creates. A run that varies only the number of files was not done.
- The first restore at 50 GiB is a re-run after an attempt was invalidated when the lid of the Mac closed during the measurement, so it is the second restore from the same backup.
- Whether the read-back after a restore was served from storage-side cache is a caveat, given the S3-Burst record (98.5% to 99.9% of reads of a 280 GiB data set did not reach the disk). A restored volume is a new volume, so the effect is thought to be small, but it was not checked.
- The earlier record (the Hub copy and restore, 2026-08-28, about 9.4 MiB of data) has a different environment and number of runs, so it is not placed side by side with these values.
## M3 results: AWS Backup restore testing
**In progress.** The plan is to measure restore testing four times against one recovery point of a 1 GiB volume (one large file) backed up with AWS Backup. One run has been recorded so far. Unit is seconds. Environment: Tokyo Region, generation 1 SINGLE_AZ_1, throughput capacity 128 MBps, ONTAP 9.19.1P4, measured 2026-11-21 (UTC).
| Measurement | n | Value (seconds) | Interval definition |
|---|---|---|---|
| Backup creation (`backup-create`) | 1 | 241.4 | Backup job creation to completion |
| Restore job (`restore_job_seconds`) | 1 | 496.1 | Restore job creation to completion (AWS Backup timestamps) |
| Start wait (`start_wait_seconds`) | 1 | 594.2 | From the scheduled time (22:50 UTC) to the creation of the restore job |
- The start wait is the time from the time set by the restore testing plan to AWS Backup creating the restore job, and it is not included in `restore_job_seconds`. This is one observation; whether the wait is this long each time was not checked.
- The restored volume belongs to AWS Backup. It was not mounted, and its content was not checked (no full SHA-256 check). No validation is written by design, so the validation status is expected to end as TIMED_OUT (it is not in the run record). The value is the restore job duration, not the time until the data can be read after a restore (`S_restore`). The tier for the content of this group is `hypothesis`.
- After the restore job completed, AWS Backup took 4373.9 seconds to delete the restored volume automatically.
- The first attempt failed at plan creation because the driver role lacked an IAM permission (`backup:TagResource`). That record was kept apart as invalid. The record of the second attempt was written after a resume, because the process that created the plan stopped before it wrote the record. The environment clocks were read at the resume, not at the start of the test.
- Of the four planned runs, the rest are in progress or not yet recorded, and a range cannot be given for n=1. This table is interim until all four are in.
## M4 results: clean rebuild
Not started. Numbers will be added after the measurement.
## M5 results: SnapMirror
Not started. Numbers will be added after the measurement.
## M6 results: CloudWatch metrics and backup job states
Not started. Numbers will be added after the measurement.
## Variance and how to read differences
- The minimum and maximum at n=4 are a range, not a confidence interval. No p95 is given (fewer than 20 samples).
- Read a difference against the variance of an unchanged configuration (the range of the same group). A difference whose ranges overlap cannot be told from noise.
- A difference of about 1 second is within the 1-second resolution and the clock error of about 2 seconds.
- A single large value, such as the 15.0 seconds of the 50 GiB restore, was not investigated. It has not been reproduced.
- The `capability-probe` groups check capabilities and are not timing measurements (n=0). The aggregate command for all of M1 returns exit code 1 because it includes these groups; the per-group aggregates return exit code 0.
## Production estimate
None. The values in this document are a sample run on one file system and are not a production estimate. With a different data size, number of files, file shape, throughput capacity, generation or concurrent load, the values change. In your own environment, remeasure by the [steps in the guide](recovery-objectives-guide.md#measuring-the-intervals-in-your-own-environment).
## What was not measured
- Other Regions, second generation, SINGLE_AZ_2 and MULTI_AZ, throughput capacity other than 128 MBps.
- Data sizes above 50 GiB, and file counts other than the one 10 GiB small-file set. A comparison that changes only the number of files.
- Concurrent read and write load during restore or clone creation.
- The 10 GiB clone creations remeasured on 9.19.1P4 (not remeasured, by the maintainer's decision).
- The remaining M3 runs and the items of M4 to M6 (the sections above).
- From detection to the recovery declaration, the choice of recovery point, and the cutover (S_detect, S_decide, S_prepare and S_cutover of RTO).

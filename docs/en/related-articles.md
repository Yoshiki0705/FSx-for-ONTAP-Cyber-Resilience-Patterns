# Related Articles Index

Published articles covering the detection and automated response capabilities that integrate with this repository's cyber-resilience architecture.

## Automated Access Blocking (Respond Layer)

These articles describe the automated response module (`ontap_response.py`) from the companion [FSx-for-ONTAP-Observability-integrations](https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations) repository. The module implements storage-layer access blocking triggered by any detection source via SNS — the same Respond-phase mechanism that connects to this repo's event-driven response layer.

| Article | Language | Platform | Published |
|---------|----------|----------|-----------|
| [Automated Access Blocking for FSx for ONTAP — From Ransomware Detection to Storage-Layer Deny](https://dev.to/aws-builders/automated-access-blocking-for-fsx-for-ontap-from-ransomware-detection-to-storage-layer-deny-4l2g) | EN | dev.to (AWS Builders) | 2026-07 |
| [Amazon FSx for NetApp ONTAP の自動アクセス遮断 — ランサムウェア検知からストレージ層ブロックまで](https://hakobiya.hatenablog.com/entry/fsxn-automated-incident-response) | JA | hatena blog | 2026-07 |

### Topics Covered

- End-to-end flow: ARP/AI detection → EMS event → observability monitor → SNS → Lambda → ONTAP REST API blocking (under 2 minutes)
- SMB user blocking via name-mapping deny + session disconnect
- NFS IP blocking via export-policy deny + NACL deny (network-layer immediate cutoff)
- Snapshot storm prevention (cooldown-based deduplication)
- Verified-clean recovery point workflow (FlexClone + isolated S3 AP scan)
- NIST CSF 2.0 positioning (Respond function — RS.MI + RS.AN)
- Comparison with NetApp Data Infrastructure Insights (DII) Storage Workload Security (same ONTAP mechanisms, different detection source). DII here is the NetApp product, not Deep Instinct
- 52 unit tests, CLI helper, multi-SVM fan-out

### Mapping to This Repo's Layers

| Article Section | This Repo's Layer | Relevant Path |
|-----------------|-------------------|---------------|
| Architecture (SNS → Lambda → ONTAP REST API) | Event-driven response | `solutions/event-driven-response/` |
| ARP/AI detection flow | Storage-native (ARP) | `solutions/ontap-native/` |
| NACL deny for NFS | Network layer | `templates/network.yaml` |
| Snapshot creation & recovery verification | Data protection | `templates/dr-replication.yaml` |
| NIST CSF 2.0 capability map | Framework mapping | [`cyber-resilience-framework-mapping.md`](cyber-resilience-framework-mapping.md) |
| DII Storage Workload Security comparison | Event-driven response (companion repo) | [Automated response guide FAQ](https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations/blob/main/docs/en/automated-response-guide.md#faq) |

## Series Context

The articles above are Part 18 (EN) / Part 6 (JA) of the "Serverless Observability for FSx for ONTAP" series. Earlier parts in the series that are directly relevant to this repo:

| Part (EN) | Part (JA) | Topic | Relevance to This Repo |
|-----------|-----------|-------|------------------------|
| Part 3 | Part 2 | ARP + FPolicy event-driven detection | `solutions/ontap-native/` — ARP configuration patterns |
| Part 17 | Part 5 | CloudWatch Log Alarm (no Metric Filter) | `templates/observability.yaml` — alarm patterns |
| Part 18 | Part 6 | Automated access blocking | `solutions/event-driven-response/` — response orchestration |

## GitHub Source References

The implementation code referenced in the articles lives in the observability repo:

- **Response module**: [`shared/python/ontap_response.py`](https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations/blob/main/shared/python/ontap_response.py)
- **CloudFormation template**: [`shared/templates/automated-response.yaml`](https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations/blob/main/shared/templates/automated-response.yaml)
- **TTL auto-unblock**: [`shared/templates/automated-response-ttl.yaml`](https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations/blob/main/shared/templates/automated-response-ttl.yaml)
- **Recovery verification**: [`shared/templates/restore-verification.yaml`](https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations/blob/main/shared/templates/restore-verification.yaml)
- **CLI helper**: [`shared/scripts/automated-response-cli.sh`](https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations/blob/main/shared/scripts/automated-response-cli.sh)
- **Detailed guide**: [`docs/en/automated-response-guide.md`](https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations/blob/main/docs/en/automated-response-guide.md)
- **NIST CSF 2.0 map**: [`docs/en/cyber-resilience-capability-map.md`](https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations/blob/main/docs/en/cyber-resilience-capability-map.md)
- **Security addendum**: [`docs/en/automated-response-security-addendum.md`](https://github.com/Yoshiki0705/FSx-for-ONTAP-Observability-integrations/blob/main/docs/en/automated-response-security-addendum.md)

## How to Use This Information

If you are deploying this repo's cyber-resilience stack and want the automated blocking capability:

1. Deploy this repo's infrastructure first (network, storage, events)
2. Deploy the observability repo's `automated-response.yaml` stack
3. Wire your detection monitors (CloudWatch Alarm, Datadog, Elastic) to the SNS trigger topic
4. Test with `automated-response-cli.sh test` (dry-run, no actual block)
5. Run a full drill with a test user on a test SVM

See [companion-repos-integration.md](companion-repos-integration.md) for the complete deployment sequence and layer mapping.

# Security Monitoring Design

## 概要 / Overview

セキュリティイベントの収集、フィルタリング、可視化、アラートの設計。
既存の FSx-for-ONTAP-Observability-integrations プロジェクトを基盤とし、本プロジェクトではセキュリティ特化の監視を追加。

## FSx-for-ONTAP-Observability-integrations との責務分担

| Aspect | FSx-for-ONTAP-Observability-integrations | This project |
|--------|-------------------------------|--------------|
| 監査ログ収集・SIEM 配信 | ✅ Primary | 参照のみ |
| セキュリティイベントフィルタリング | — | ✅ Primary |
| ARP/FPolicy/Scanner アラート | — | ✅ Primary |
| ダッシュボード (general) | ✅ | — |
| ダッシュボード (security) | — | ✅ Primary |
| SIEM 連携（基盤） | ✅ | — |
| SIEM 相関ルール（セキュリティ） | — | ✅ Primary |

## CloudWatch Metrics

### Custom Metrics (Published by Lambda functions)

| Metric | Namespace | Unit | Description |
|--------|-----------|------|-------------|
| `SecurityEventsReceived` | FsxOntapCyberResilience | Count | SQS から受信したイベント数 |
| `MalwareDetected` | FsxOntapCyberResilience | Count | マルウェア検知数 |
| `RansomwareAlerts` | FsxOntapCyberResilience | Count | ARP ランサムウェアアラート数 |
| `QuarantineExecuted` | FsxOntapCyberResilience | Count | 隔離ワークフロー実行数 |
| `ScanLatencyP99` | FsxOntapCyberResilience | Milliseconds | スキャンレイテンシ p99 |
| `FalsePositives` | FsxOntapCyberResilience | Count | 管理者が FP と判定した件数 |
| `DlqMessages` | FsxOntapCyberResilience | Count | DLQ にあるメッセージ数 |

### AWS Service Metrics (Automatic)

| Service | Key Metrics |
|---------|------------|
| SQS | ApproximateNumberOfMessagesVisible, ApproximateAgeOfOldestMessage |
| Lambda | Errors, Duration, Throttles |
| Step Functions | ExecutionsFailed, ExecutionsTimedOut |
| EventBridge | FailedInvocations |

## CloudWatch Alarms

| Alarm | Metric | Threshold | Action |
|-------|--------|-----------|--------|
| DLQ Messages | SQS ApproximateNumberOfMessagesVisible | ≥ 1 | SNS → Security team |
| Malware Burst | MalwareDetected (5 min sum) | ≥ 10 | SNS → CRITICAL alert |
| Ransomware Alert | RansomwareAlerts | ≥ 1 | SNS → CRITICAL + PagerDuty |
| Scan Latency High | ScanLatencyP99 | > 100ms | SNS → Performance team |
| Lambda Errors | Lambda Errors (5 min) | ≥ 3 | SNS → DevOps team |
| Step Functions Failure | ExecutionsFailed | ≥ 1 | SNS → Security team |

## Log Retention Policy

| Log Source | Retention | Rationale |
|-----------|-----------|-----------|
| Lambda function logs | 90 days | Standard operational |
| Step Functions execution logs | 90 days | Audit trail |
| Security event logs (S3) | 365 days | Compliance (configurable) |
| SnapLock evidence | 7 years max | Regulatory retention |

## SIEM Integration Event Format

Events are published to EventBridge in the following format (see `solutions/event-driven-response/schemas/security-event.json`):

```json
{
  "source": "fsxn.cyber-resilience.fpolicy",
  "detail-type": "MalwareDetected",
  "detail": {
    "fileSystemId": "fs-0123456789abcdef0",
    "svmId": "svm-0123456789abcdef0",
    "volumeId": "fsvol-0123456789abcdef0",
    "filePath": "/production/documents/malicious.exe",
    "operation": "create",
    "clientIp": "10.0.x.x",
    "userName": "DOMAIN\\user1",
    "verdict": "MALICIOUS",
    "scannerName": "trendai",
    "severity": "CRITICAL",
    "timestamp": "2026-06-25T10:30:00Z"
  }
}
```

SIEM 連携時はこのフォーマットを各 SIEM の ingest format に変換（Lambda transformer）。

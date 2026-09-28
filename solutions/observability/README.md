# Observability — Security Monitoring

## Overview

セキュリティイベントの CloudWatch カスタムメトリクス発行とダッシュボード構成を提供する。

## Components

| Module | Purpose |
|--------|---------|
| `security_metrics.py` | CloudWatch カスタムメトリクス publisher (Lambda 内で利用) |
| `dashboard_config.py` | CloudWatch Dashboard JSON 生成 (CloudFormation テンプレートで利用) |

## Custom Metrics (Namespace: `FsxOntapCyberResilience`)

| Metric | Unit | Description |
|--------|------|-------------|
| SecurityEventsReceived | Count | SQS から受信したイベント数 |
| MalwareDetected | Count | マルウェア検知数 (Scanner dimension 付き) |
| RansomwareAlerts | Count | ARP ランサムウェアアラート数 |
| QuarantineExecuted | Count | 隔離ワークフロー実行数 |
| ScanLatencyP99 | Milliseconds | スキャンレイテンシ p99 |
| FalsePositives | Count | 管理者が FP と判定した件数 |
| DlqMessages | Count | DLQ メッセージ数 |

## Usage

```python
from security_metrics import SecurityMetricsPublisher

metrics = SecurityMetricsPublisher(environment="dev")
metrics.record_malware_detected(scanner_name="trendai")
metrics.record_scan_latency(latency_ms=25.3)
```

## Integration

- FSx-for-ONTAP-Observability-integrations: 監査ログ収集・SIEM 配信 (別リポジトリ)
- 本モジュール: セキュリティ特化のメトリクス・ダッシュボード・アラート

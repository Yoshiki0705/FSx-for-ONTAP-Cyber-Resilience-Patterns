# Scanner Failover Runbook

## 概要 / Overview

スキャナーインスタンス障害時の対応手順。ASG による自動復旧と手動介入が必要なケースを区別する。

## トリガー / Trigger

- CloudWatch Alarm: `ScannerHealthy` = 0 for any instance
- ASG イベント: EC2 instance terminated (unhealthy)
- FPolicy passthrough notification (scanner unreachable)

## 自動復旧 (ASG) / Automatic Recovery

Phase 2 の HA 構成では、ASG が自動的に:
1. 不健全なインスタンスを検知 (EC2 status check)
2. インスタンスを terminate
3. 新しいインスタンスを別 AZ で起動
4. FPolicy は secondary server にフェイルオーバー (< 30s)

**対応不要な場合**: ASG が正常に置換し、Health Check Lambda が回復を確認

## 手動介入が必要な場合 / Manual Intervention

| Scenario | Action |
|----------|--------|
| ASG が新インスタンスを起動できない (capacity 不足) | Instance type 変更 or 別 AZ 指定 |
| 新インスタンスも ICAP 応答しない | AMI 問題 → Launch Template 確認 |
| 全 AZ のスキャナーが同時障害 | FPolicy passthrough で業務継続 → 根本原因調査 |

## 手順 / Procedure

### 1. 状況確認

```bash
# ASG のインスタンス状態
aws autoscaling describe-auto-scaling-groups \
  --auto-scaling-group-names fsxn-cyber-resilience-vscan-asg-dev \
  --query 'AutoScalingGroups[0].Instances[*].[InstanceId,HealthStatus,LifecycleState,AvailabilityZone]' \
  --output table

# Health Check メトリクス
aws cloudwatch get-metric-statistics \
  --namespace FsxOntapCyberResilience \
  --metric-name ScannerHealthy \
  --start-time $(date -u -v-1H +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 60 --statistics Minimum \
  --dimensions Name=Environment,Value=dev Name=Project,Value=fsxn-cyber-resilience
```

### 2. FPolicy 状態確認 (passthrough mode)

```bash
ssh fsxadmin@<management-ip>
fpolicy show -vserver svm-prod-dev -fields status,server-status
```

### 3. 強制的なインスタンス更新

```bash
aws autoscaling start-instance-refresh \
  --auto-scaling-group-name fsxn-cyber-resilience-vscan-asg-dev \
  --preferences '{"MinHealthyPercentage": 50}'
```

## エスカレーション / Escalation

| Condition | Escalate to |
|-----------|-------------|
| 30分以上全スキャナー不可 | Security lead + Storage lead |
| FPolicy mandatory モードで I/O ブロック中（**NFS / SMB のみ。S3 Access Point 経由の I/O はブロックされず通り続ける**） | Immediate: Storage lead |
| AMI/Launch Template 問題 | DevOps lead |

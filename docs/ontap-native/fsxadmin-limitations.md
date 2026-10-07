# fsxadmin Permissions & Limitations

## 概要 / Overview

FSx for ONTAP は AWS マネージドサービスのため、ONTAP の `cluster admin` ロールは利用不可。
代わりに `fsxadmin` ユーザー（SVM-scoped の vsadmin 相当 + 一部の cluster-level 権限）を使用する。

FSx for ONTAP is a managed service — the cluster admin role is unavailable.
Instead, use the `fsxadmin` user which has vsadmin-equivalent permissions plus select cluster-level access.

## 利用可能な操作 / Available Operations

### ストレージ管理

| Operation | Available | Notes |
|-----------|-----------|-------|
| Volume create/modify/delete | ✅ | via CloudFormation or CLI |
| SVM create/modify/delete | ✅ | via CloudFormation or CLI |
| Aggregate management | ❌ | AWS managed |
| Disk assignment | ❌ | AWS managed |
| Storage capacity increase | ✅ | via AWS Console/API or CLI |
| Throughput capacity change | ✅ | via AWS Console/API |

### セキュリティ機能

| Operation | Available | Notes |
|-----------|-----------|-------|
| ARP enable/disable | ✅ | per volume |
| ARP learning → active | ✅ | |
| FPolicy create/modify/delete | ✅ | per SVM |
| SnapLock volume create | ✅ | via CloudFormation |
| SnapLock retention modify (extend) | ✅ | shorten is not possible |
| Tamperproof Snapshot enable | ✅ | |
| MAV enable/configure | ✅ | |
| Vscan enable/configure | ✅ | |

### ネットワーク

| Operation | Available | Notes |
|-----------|-----------|-------|
| LIF management | ❌ | AWS managed (ENI-based) |
| Route management | Limited | SVM-level routes only |
| DNS/NIS configuration | ✅ | per SVM |
| Export policy create/modify | ✅ | |

### データ保護

| Operation | Available | Notes |
|-----------|-----------|-------|
| Snapshot create/delete | ✅ | |
| Snapshot policy create/modify | ✅ | |
| SnapMirror create/manage | ✅ | |
| FlexClone create | ✅ | |
| AWS Backup integration | ✅ | Via AWS Console/API. RW volumes only; DP, LSM, FlexCache and SnapMirror destination volumes and SnapLock FlexGroup volumes are not backed up [E-010]. To copy backups to a logically air-gapped vault, the file system must be encrypted with a customer managed key [E-009]. See the [vault guide](../data-protection/aws-backup-logically-air-gapped-vault.md) |

### 監査・監視

| Operation | Available | Notes |
|-----------|-----------|-------|
| Audit log enable | ✅ | per SVM |
| EMS event view | ✅ | |
| Performance monitoring | ✅ | via CLI or REST API |

## 利用不可の操作 / Unavailable Operations

以下は AWS が管理するため、fsxadmin では実行不可:

- Cluster peer create (use AWS Console for cross-region)
- Network interface (LIF) create/modify/delete
- Aggregate create/modify
- Node management
- Service processor access
- Firmware updates
- HA failover manual trigger (use AWS Console)
- Cluster-level security certificates management

## AWS サポートリクエストが必要な操作

一部の操作は AWS サポートへの連絡が必要:

- ARP 学習データのリセット
- SnapLock Compliance clock の調整（極めて稀）
- 特定のバグ修正パッチ適用
- cluster-level のパフォーマンスチューニング

## REST API アクセス

```bash
# Management endpoint format
https://<file-system-dns-name>/api/...

# Authentication
# Basic Auth with fsxadmin:<password>
# Or certificate-based (recommended for automation)

# Example: List volumes
curl -X GET "https://management.<fs-id>.fsx.<region>.amazonaws.com/api/storage/volumes" \
  -H "Authorization: Basic $(echo -n fsxadmin:<password> | base64)" \
  -k
```

## Custom Resource Lambda での利用

Lambda-backed CloudFormation Custom Resource から ONTAP REST API を呼ぶ場合の注意:

1. **認証情報**: Secrets Manager に格納（`FsxAdminPassword` パラメータを Secrets Manager に移行推奨）
2. **ネットワーク**: Lambda を VPC 内に配置し、FSx management ENI に到達可能にする
3. **タイムアウト**: Lambda タイムアウトを 300秒に設定（ONTAP API 応答が遅い場合あり）
4. **TLS**: FSx の自己署名証明書のため `verify=False` または CA 証明書取得が必要
5. **冪等性**: Create/Update ハンドラは冪等に実装（リトライ対応）

```python
# Example: Custom Resource Lambda (conceptual)
import boto3
import requests
import json

def handler(event, context):
    secrets = boto3.client('secretsmanager')
    creds = json.loads(
        secrets.get_secret_value(SecretId='fsxn-cyber-resilience-fsxadmin')['SecretString']
    )
    
    mgmt_ip = event['ResourceProperties']['ManagementEndpoint']
    session = requests.Session()
    session.auth = ('fsxadmin', creds['password'])
    session.verify = False  # FSx self-signed cert
    
    # Perform ONTAP API call based on event type
    if event['RequestType'] == 'Create':
        # Enable ARP, configure FPolicy, etc.
        pass
```

## 参照 / References

- [FSx for ONTAP — Administrative access](https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/managing-resources-ontap-apps.html)
- [FSx for ONTAP — ONTAP REST API](https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/ontap-rest-api.html)

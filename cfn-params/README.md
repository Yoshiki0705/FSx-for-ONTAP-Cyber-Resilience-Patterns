# cfn-params/ — CloudFormation Parameter Files

## Usage

These files use the standard `create-stack` / `update-stack` parameter format:

```bash
aws cloudformation create-stack \
  --stack-name <stack-name> \
  --template-body file://templates/<template>.yaml \
  --parameters file://cfn-params/<file>.example.json \
  --capabilities CAPABILITY_NAMED_IAM \
  --region ap-northeast-1
```

> **Note**: `aws cloudformation deploy` does **not** support `file://` for parameters.
> Use `create-stack` or `update-stack` with `--parameters file://...` instead.

## File Naming Convention

| File | Template | Deployment Path |
|------|----------|-----------------|
| `network.example.json` | `network.yaml` | Greenfield (new VPC) |
| `network-existing-vpc.example.json` | `network.yaml` | Brownfield (existing VPC) |
| `storage.example.json` | `storage.yaml` | New FSx for ONTAP |
| `storage-existing.example.json` | `storage.yaml` | Existing FSx for ONTAP |
| `event-driven.example.json` | `event-driven.yaml` | Both paths |
| `scanning.example.json` | `scanning.yaml` | Both paths |
| `scanning-ha.example.json` | `scanning-ha.yaml` | HA scanner deployment |
| `observability.example.json` | `observability.yaml` | Both paths |
| `cost-scheduler.example.json` | `cost-scheduler.yaml` | Non-production cost savings |
| `hub-aggregation.example.json` | `hub-aggregation.yaml` | Central hub account |
| `spoke-monitoring.example.json` | `spoke-monitoring.yaml` | Workload accounts |
| `siem-integration.example.json` | `siem-integration.yaml` | Security Hub / SIEM |
| `main.example.json` | `main.yaml` | Nested stack orchestration |
| `demo-ad-environment.example.json` | `shared/templates/demo-ad-environment.yaml` | AD demo environment (Pattern A) |

## AD Environment — Mode Decision Tree

The `demo-ad-environment.yaml` template supports three AD modes via the `AdMode` parameter.
Use the following decision tree to choose the right mode:

```
Do you already have an Active Directory?
│
├── NO
│   └── AdMode = "create-new"  (Pattern A)
│       Creates a new AWS Managed Microsoft AD.
│       Provides: DirectoryId, DNS IPs, domain join automation.
│       Cost: ~$0.12/hr (Standard) or ~$0.24/hr (Enterprise).
│
└── YES
    │
    ├── Is it AWS Managed Microsoft AD (via Directory Service)?
    │   └── YES → AdMode = "use-existing-managed"  (Pattern B)
    │       Provide: ExistingDirectoryId (e.g., d-0123456789)
    │       Domain join via SSM Document (same as Pattern A).
    │
    └── NO (EC2-hosted AD / on-premises AD / AD Connector)
        └── AdMode = "use-self-managed"  (Pattern C)
            Provide: SelfManagedDomainName, SelfManagedDnsIps,
                     SelfManagedAdUsername, SelfManagedAdPassword
            Optional: SelfManagedAdOu (custom OU for computer objects)
            Domain join: manual or via SVM AD join script.
```

### AD Port Requirements

Ensure the following ports are open between FSx for ONTAP ENIs and AD domain controllers:

| Protocol | Port | Service |
|----------|------|---------|
| TCP | 53 | DNS |
| TCP | 88 | Kerberos authentication |
| TCP | 389 | LDAP |
| TCP | 445 | SMB / CIFS |
| TCP | 636 | LDAPS (LDAP over TLS) |
| TCP | 3268 | Global Catalog |
| TCP | 9389 | AD Web Services (PowerShell) |
| UDP | 53 | DNS |
| UDP | 88 | Kerberos authentication |
| UDP | 389 | LDAP |

### SVM AD Join (post-deployment)

After deploying the AD environment, join the FSx for ONTAP SVM to the domain:

```bash
# Pattern A (from stack outputs):
./shared/scripts/demo-ad-join-svm.sh \
  --svm-id svm-0123456789abcdef0 \
  --ad-stack-name fsxn-cyber-resilience-demo-ad-dev

# Pattern C (explicit parameters):
./shared/scripts/demo-ad-join-svm.sh \
  --svm-id svm-0123456789abcdef0 \
  --domain onprem.example.com \
  --dns-ips 198.51.100.10,198.51.100.11 \
  --ou "OU=FSxComputers,DC=onprem,DC=example,DC=com"
```

## Customization

1. Copy the example file: `cp cfn-params/network.example.json cfn-params/network-myenv.json`
2. Replace placeholder values (marked `REPLACE_WITH_*`)
3. Update resource IDs to match your environment
4. For passwords/secrets, prefer Secrets Manager over plain-text values

## IP Addresses in Examples

Example files use [RFC 5737](https://datatracker.ietf.org/doc/html/rfc5737) documentation
addresses (`198.51.100.0/24`) for CIDR blocks. Replace with your actual VPC CIDR.

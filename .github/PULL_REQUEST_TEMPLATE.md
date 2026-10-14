## Summary

<!-- Brief description of what this PR does -->

## Changes

- 

## Checklist

- [ ] `make lint` passes (cfn-lint clean)
- [ ] `make test` passes (all pytest green)
- [ ] No forbidden naming (`FSxN`, bare `FSx`); management-plane tools named officially (NetApp Console, NetApp Workload Factory)
- [ ] No real AWS account IDs, IPs, or resource IDs committed
- [ ] No vendor-versus language ("better than", "beats", "inferior")
- [ ] CloudFormation resources have required tags (Project, Environment, Layer)
- [ ] Documentation updated (if behavior changed)
- [ ] Bilingual content maintained (JA/EN parity where applicable)

## Security Layer

Which layer(s) does this PR affect?

- [ ] Storage-native (ARP, FPolicy, SnapLock, MAV)
- [ ] File scanning (TrendAI, Deep Instinct)
- [ ] Event-driven response (SQS, EventBridge, Step Functions)
- [ ] Observability (CloudWatch, SIEM)
- [ ] Data protection (Snapshot, SnapMirror, FlexClone)
- [ ] Infrastructure (network, IAM, KMS)
- [ ] CI/CD / Tooling
- [ ] Documentation only

## Testing

<!-- How was this tested? -->

- [ ] cfn-lint validation
- [ ] pytest unit tests
- [ ] cfn-guard security rules
- [ ] Manual deployment to dev (if applicable)

## Related Issues

<!-- Link related issues: Fixes #XX, Relates to #XX -->

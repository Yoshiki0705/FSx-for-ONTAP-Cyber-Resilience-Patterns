# Verifying the Alert Path After Deployment

🌐 **English** | [日本語](../ja/alert-path-verification.md)

This procedure deploys the stacks to a test environment and checks that alerts reach a receiver. It covers the alert topic key and policy in `event-driven.yaml`, the quarantine workflow's data flow and error handling, the `QuarantineExecutionsFailedAlarm` alarm, and the hub alert topic in `hub-aggregation.yaml`. The results in the [deployment guide](deployment-guide.md#security-alert-topic-encryption) come from standalone resources. These steps run the same checks on the deployed templates.

## What This Checks

| # | Question | Where |
|---|----------|-------|
| 1 | Does changing an existing topic from the AWS managed key `aws/sns` to the customer managed key avoid replacing the topic? | Step 2 |
| 2 | Can the Step Functions role publish to the encrypted topic? | Step 5, C3 |
| 3 | Do an alarm and an EventBridge rule deliver to the topic in the deployed stack? | Step 5, C1 and C2 |
| 4 | Does the `ExecutionsFailed` alarm fire with its 300-second period? | Step 5, C4 |
| 5 | Does the hub rule deliver to the hub topic, and is the hub bus policy what you intend? | Step 6 |

These steps do not check four things:

- The approval path from `WaitForApproval` onward. It needs ONTAP, so it needs a deployment with FSx for ONTAP (Quickstart pattern B).
- The `NotificationFailed` end state. It needs an SNS failure to be injected.
- The KMS permission of `ComplianceCollectorRole` in `siem-integration.yaml`. It needs that stack.
- Events forwarded from a spoke account to the hub bus. It needs a second account.

## Prerequisites

- An AWS account for testing, and an IAM Identity Center session for the AWS CLI (`aws sso login`).
- An S3 bucket for the Lambda packages. The deployment script reads its name from `LAMBDA_ARTIFACT_BUCKET`.
- The deployment time and cost of the pipeline-only stacks are in [Quickstart, pattern A](../quickstart-deployment.md). Steps 1 and 3 create these resources, so decide on the cost first.

## Step 0: Prepare

```
aws sso login
export AWS_REGION=ap-northeast-1
export LAMBDA_ARTIFACT_BUCKET=<your bucket name>
git worktree add --detach ../fsxn-cyber-old 7654c64
git worktree add --detach ../fsxn-cyber-new origin/main
```

Commit `7654c64` is the state before the alert topic key change. `fsxn-cyber-new` holds the current templates. Using separate worktrees keeps your main checkout untouched.

## Step 1: Deploy the Previous Version

Run these in `fsxn-cyber-old`. This is the pipeline-only deployment from the Quickstart, without FSx for ONTAP.

```
./scripts/deploy.sh dev package
./scripts/deploy.sh dev network
./scripts/deploy.sh dev events
./scripts/deploy.sh dev observability
```

The update in Step 3 then starts from a stack that has a topic encrypted with `aws/sns`.

## Step 2: Preview the Update with a Change Set

Run this in `fsxn-cyber-new`. It changes nothing.

```
aws cloudformation create-change-set --stack-name fsxn-cyber-resilience-events-dev --change-set-name main-check --template-body file://templates/event-driven.yaml --capabilities CAPABILITY_NAMED_IAM --parameters ParameterKey=ProjectName,UsePreviousValue=true ParameterKey=Environment,UsePreviousValue=true ParameterKey=NotificationEmail,UsePreviousValue=true ParameterKey=LambdaArtifactBucket,UsePreviousValue=true ParameterKey=LambdaArtifactPrefix,UsePreviousValue=true ParameterKey=EventTransformerS3Key,UsePreviousValue=true ParameterKey=QuarantineActionS3Key,UsePreviousValue=true ParameterKey=LogGroupKmsKeyArn,UsePreviousValue=true ParameterKey=LambdaEnvKmsKeyArn,UsePreviousValue=true
aws cloudformation wait change-set-create-complete --stack-name fsxn-cyber-resilience-events-dev --change-set-name main-check
aws cloudformation describe-change-set --stack-name fsxn-cyber-resilience-events-dev --change-set-name main-check --query 'Changes[].ResourceChange.[LogicalResourceId,Action,Replacement]' --output table
```

| Row for `SecurityAlertTopic` | Decision |
|------------------------------|----------|
| `Modify` and `False` | Go to Step 3 |
| `True` or `Conditional` | Stop. A replaced topic gets a new ARN and loses its subscriptions |

The expected result is `Modify` and `False`. This was not checked. The same table should also list `AlertTopicKey`, `SecurityAlertTopicPolicy` and `QuarantineExecutionsFailedAlarm` as `Add`.

## Step 3: Apply the Update

```
aws cloudformation execute-change-set --stack-name fsxn-cyber-resilience-events-dev --change-set-name main-check
aws cloudformation wait stack-update-complete --stack-name fsxn-cyber-resilience-events-dev
./scripts/deploy.sh dev observability
```

If the update fails, CloudFormation rolls back to `UPDATE_ROLLBACK_COMPLETE` by itself.

## Step 4: Subscribe a Receiving Queue

An SQS queue shows mechanically whether a notification arrived. An email subscription needs a confirmation click.

```
aws cloudformation describe-stacks --stack-name fsxn-cyber-resilience-events-dev --query "Stacks[0].Outputs[?OutputKey=='SecurityAlertTopicArn'].OutputValue" --output text
aws sqs create-queue --queue-name deploycheck-q
aws sqs get-queue-attributes --queue-url <queue URL> --attribute-names QueueArn
```

In the queue policy, allow `sqs:SendMessage` from the topic, with `aws:SourceArn` set to the topic ARN. Then subscribe the queue.

```
aws sns subscribe --topic-arn <topic ARN> --protocol sqs --notification-endpoint <queue ARN>
```

## Step 5: Run the Checks

Read each result with `aws sqs receive-message --queue-url <queue URL> --wait-time-seconds 20 --max-number-of-messages 10`.

| # | Action | Expected result |
|---|--------|-----------------|
| C1 | `aws cloudwatch set-alarm-state --alarm-name fsxn-cyber-resilience-dlq-messages-dev --state-value ALARM --state-reason deploy-check` | An `ALARM` notification in the queue, and `Successfully executed action` in the alarm history |
| C2 | `aws events put-events --entries '[{"Source":"fsxn.cyber-resilience.probe","DetailType":"DeployCheck","Detail":"{}","EventBusName":"<SecurityEventBusName output>"}]'` | The event body in the queue |
| C3 | `aws stepfunctions start-execution --state-machine-arn <QuarantineStateMachineArn output> --input '{"detail":{"timestamp":"2026-01-01T00:00:00Z","volumeId":"fsvol-0123456789abcdef0","svmId":"svm-0123456789abcdef0","severity":"HIGH"}}'` | The execution ends `SUCCEEDED`, and the queue holds `ERROR: Quarantine Workflow Failed`. The volume does not exist, so the snapshot fails and `NotifyFailure` publishes through the role |
| C4 | `aws stepfunctions start-execution --state-machine-arn <QuarantineStateMachineArn output> --input '{}'` | The execution ends `FAILED`. After a few minutes `fsxn-cyber-resilience-quarantine-executions-failed-dev` reaches `ALARM` and the queue holds the notification |

The event in C2 uses a source and detail type that the quarantine rule does not match, so it starts no workflow. The time C4 takes was not measured. A test with a 60-second period took 104 seconds.

How to read a failure:

- If only C1 fails, suspect the key policy.
- If only C2 fails, suspect the topic policy.
- If only C3 fails, suspect the KMS permission of the Step Functions role.

## Step 6: Hub Stack

Deploy the hub stack with an organization ID:

```
aws cloudformation deploy --template-file templates/hub-aggregation.yaml --stack-name fsxn-cyber-resilience-hub-dev --parameter-overrides OrganizationId=<organization ID>
aws cloudformation describe-stacks --stack-name fsxn-cyber-resilience-hub-dev --query "Stacks[0].Outputs[?OutputKey=='HubAlertTopicArn'].OutputValue" --output text
aws events describe-event-bus --name fsxn-cyber-resilience-hub-dev --query Policy --output text
```

Subscribe a queue to the hub topic as in Step 4, then send an event to the hub bus:

```
aws events put-events --entries '[{"Source":"fsxn.cyber-resilience.fpolicy","DetailType":"MalwareDetected","Detail":"{}","EventBusName":"fsxn-cyber-resilience-hub-dev"}]'
```

The event body in the queue means the hub rule delivers to the hub topic.

Check the bus policy. The `describe-event-bus` output must show `"Principal":"*"` together with a `StringEquals` condition on `aws:PrincipalOrgID` that holds your organization ID. `OrganizationId` is required and must match `o-` followed by 10 to 32 lowercase letters or digits. An earlier version of the template accepted an empty value and dropped the condition's `Value`; in one deployment (ap-northeast-1) EventBridge rejected that with a null `condition.value` error and the policy resource failed to create.

## Step 7: Clean Up

```
aws cloudformation delete-stack --stack-name fsxn-cyber-resilience-hub-dev
aws cloudformation delete-stack --stack-name fsxn-cyber-resilience-observability-dev
aws cloudformation delete-stack --stack-name fsxn-cyber-resilience-events-dev
aws cloudformation delete-stack --stack-name fsxn-cyber-resilience-network-dev
```

Wait for each deletion with `aws cloudformation wait stack-delete-complete --stack-name <name>` before the next. Delete the `deploycheck-q` queue and its subscription, empty and delete the Lambda package bucket, and remove the two worktrees with `git worktree remove`.

`AlertTopicKey` and `HubAlertTopicKey` are deleted with their stacks after a 30-day waiting period. They stay in the pending-deletion state during that time. The charge for a key in that state was not checked.

## If a Step Fails

- A failed stack update rolls back by itself (Step 3). Find the cause in `aws cloudformation describe-stack-events` before you retry.
- A failed check (Step 5) does not need a stack rollback. Find the cause with the reading above, and do not move the templates to a production environment until the check passes.

## Not Measured

- No run of this procedure. The commands follow the deployment script and the template outputs, and the checks C1 to C4 were not run in a deployed stack.
- Whether the topic update in Step 2 is in place.
- The time C4 takes with the 300-second period.

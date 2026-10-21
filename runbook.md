# Alert runbook

What to do when a `[AWS ALERT]` email arrives. How it's built:
`infra/security/alerting.tf` and `alerting-rules.tf`.

## First 5 minutes (every alert)
1. **Which account, and is it me?** The email names the account by ID:
   `aws organizations list-accounts --profile management-audit --query 'Accounts[].[Id,Name]' --output table`.
   Check `by` (my SSO role, session `nojus`), `from` (my home IP) and the
   time. Was I running Terraform or the CLI right then?
   Expected → done. Not sure → treat as not me.
2. **`error: AccessDenied`** = blocked attempt. Nothing changed, but
   someone tried: still find out who.
3. **Not me** → contain first, then investigate, then write it down
   (what happened, the evidence, the fix).

## Per alert
| Alert | Usually expected when | If not me |
|---|---|---|
| Root console sign-in | I signed in as management root | Change root password + MFA now; check what root did (CloudTrail, `userIdentity.type = Root`) |
| AssumeRoot | I ran break-glass | Find who in management (`by`), which account (`targetPrincipal`) and task; revoke that SSO user's sessions |
| Change made as root | During my own break-glass session | Same as above; undo the change |
| Logging changed or stopped | My Terraform apply (Config/CloudTrail). An org-trail change alerts once per account: member copies come from `CloudTrailOrganizationReplication` | Check the trail is logging (`aws cloudtrail get-trail-status --name org-trail --profile management`); re-apply Terraform to restore |
| Threat detection changed/suppressed | My Terraform apply | A new GuardDuty filter/trusted-IP list or archive rule can hide findings: delete it, re-apply Terraform, review findings since |
| Alerting pipeline changed | My alerting changes (N rules → N emails) | If not `AccessDenied`: someone got past the SCP → management compromised; re-apply Terraform |
| Organization guardrails changed | My SCP changes / change procedure | Re-apply Terraform in management (restores SCPs); find who |
| Identity Center changed | My Identity Center Terraform | New user/assignment/permission set = persistence: remove it, revoke sessions |
| IAM user or long-lived credential | Never (no IAM users by design) | Capture details, then delete key/user; check what it did |
| New external access (Access Analyzer) | A resource I deliberately shared | Unintended → fix the policy. Intended + nobody can widen it (AWS-managed, like SSO roles) → archive rule in Terraform. Intended + editable trust (e.g. a GitHub deploy role) → archive that finding by hand in both analyzers (live/lab/… + security); a rule would silence a bad change too |
| GuardDuty finding | Sample findings I generated | Sample? (`i-99999999`, `"sample":true`). Real → open it in security, in the region from the email; contain the resource (stop instance, revoke keys) |

## Containing a compromised identity
- **SSO user:** Identity Center → user → delete active sessions; reset
  password and MFA. Role sessions last ≤ 1h (admin) / 4h (audit).
- **Root (management):** change password, replace MFA device, check for
  root access keys.
- Everything else: Terraform is the source of truth: `terraform plan`
  shows drift, `apply` restores it.

## Investigating
- First, prove the logs are intact (signed hourly digest chain):
  `aws cloudtrail validate-logs --trail-arn arn:aws:cloudtrail:us-east-1:<management-account-id>:trail/org-trail --account-id <account-id> --start-time <yyyy-mm-ddT00:00:00Z> --profile security --region us-east-1`
  (all "X/X valid" → the logs haven't been altered; don't pass `--s3-bucket`).
- Last 90 days: CloudTrail Event history in the account + region from the
  email (`aws cloudtrail lookup-events --profile <account>-audit
  --region <region> --lookup-attributes AttributeKey=Username,AttributeValue=<who>`).
- Older: the log archive `cloudtrail-logs-<security-account-id>` (security).
- Who read Terraform state or the logs? Data events are only in the
  archive's log files (not Event history), 5–15 min after the fact:
  `B=cloudtrail-logs-<security-account-id>; P=AWSLogs/<org-id>/<account-id>/CloudTrail/us-east-1/<yyyy>/<mm>/<dd>/`
  (org ID: `aws organizations describe-organization --profile management-audit --query Organization.Id --output text`),
  list the newest keys (`aws s3api list-objects-v2 … --profile security`),
  `aws s3 cp s3://$B/<key> - | zcat`, keep records with
  `eventCategory == "Data"`.

## Procedures
**Changing protected alerting** (forwarders, hub, topic: `ProtectAlerting`):
1. `aws organizations detach-policy --policy-id <policy-id> --target-id <root-id> --profile management`
   (policy ID: `aws organizations list-policies --filter SERVICE_CONTROL_POLICY --profile management`;
   root ID: `aws organizations list-roots --query 'Roots[0].Id' --output text --profile management`)
2. Plan + apply the change; wait ~1 min after step 1.
3. `terraform apply` in `infra/management` → re-attaches the SCP.
4. Verify the lock: the harmless `remove-targets` test (lab) → explicit deny.
Alerts fire at steps 1, 2, 3: expected. Same procedure for
`RestrictRegions`.
`ProtectBaseline` (baseline module changes) is attached to the Live, Lab and
Security OUs: detach it from the OU of the account being changed, or from
all three for a module-wide change; `terraform apply` in management
re-attaches.

**Break-glass (root task in a member account):** from management, e.g.
`aws sts assume-root --target-principal <account-id> --task-policy-arn
arn=arn:aws:iam::aws:policy/root-task/<Task> --profile management --region us-east-1`
Tasks: IAMAuditRootUserCredentials, IAMCreateRootUserPassword,
IAMDeleteRootUserCredentials, S3UnlockBucketPolicy, SQSUnlockQueuePolicy.
15-minute session. Expect the AssumeRoot alert.

**Monthly alert test** (silence ≠ safety): create + delete an IAM user in
lab (`aws iam create-user --user-name alert-test-<date> --profile lab`,
then `delete-user`). Expect the email within ~5 min. Nothing → check the
SNS subscription (`ConfirmationWasAuthenticated` true, not pending) and
the rules' FailedInvocations metric.

**If the email subscription is ever recreated:** don't click the
confirmation link; confirm via CLI with `--authenticate-on-unsubscribe true`
(see `infra/security/alerting.tf`).

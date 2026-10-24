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
| Access key responder changed | My responder changes (`ProtectAlerting` procedure) | Not `AccessDenied` → someone changed it: re-apply Terraform, then look for new keys (`list-access-keys` per user). `AccessDenied` → a blocked attempt in a member account (the email doesn't name the function): find who (`by`) |
| Organization guardrails changed | My SCP changes / change procedure | Re-apply Terraform in management (restores SCPs); find who |
| Identity Center changed | My Identity Center Terraform | New user/assignment/permission set = persistence: remove it, revoke sessions |
| IAM user or long-lived credential | Never (no IAM users by design); the monthly test (`error: AccessDenied`) | The responder should already have switched it off: `list-access-keys` → Inactive, log `/aws/lambda/access-key-responder`. Still Active → deactivate by hand. Then capture details, delete key/user; check what it did |
| New external access (Access Analyzer) | A resource I deliberately shared | Unintended → fix the policy. Intended + nobody can widen it (AWS-managed, like SSO roles) → archive rule in Terraform. Intended + editable trust (e.g. a GitHub deploy role) → archive that finding by hand in both analyzers (live/lab/… + security); a rule would silence a bad change too. Re-raised with no change (AWS re-analysis: every finding recreated at the same millisecond) → compare the trust policy with the code + CloudTrail, then re-archive in both analyzers |
| GuardDuty finding | Sample findings I generated | Sample? (`i-99999999`, `"sample":true`). Real → open it in security, in the region from the email; contain the resource (stop instance, revoke keys) |

## Drift check failed (GitHub email)
"Run failed: Drift check" from GitHub; the failed job names the account
(`plan (<account>)`). The change can be up to ~24h old; an `[AWS ALERT]`
for it may already be in the inbox.
1. **Exit code first:**
   `gh run view <run-id> --log-failed | grep -E -A20 "exit code|will be|Plan:|not authorized|New untagged"`
   - **1 = the check broke**, AWS is fine: usually `not authorized` (a
     resource `SecurityAudit` can't read → add the read to the role) or a
     GitHub/provider hiccup → re-run.
   - **2 = drift:** AWS differs from the code on `main`. The plan lines
     name the resource and attribute.
   - **Step "Untagged resources", exit 2:** a resource without
     `ManagedBy` that isn't in `infra/<account>/untagged-baseline.txt`
     (the log lists it). Who made it → CloudTrail; unwanted → delete;
     expected (AWS default, new service-linked role) → add the line to the
     baseline + commit. A "gone" notice → remove that line.
2. **Mine?** Applied without pushing (`git log origin/main..main`) →
   push, re-run (`gh workflow run drift.yml`). Applying at 10:17 UTC
   (`-lock=false`) → re-run.
3. **Not mine:** who and how → CloudTrail Event history in that account
   (see Investigating). Unwanted → `terraform apply` restores the code;
   a change I want to keep → update the code. Then "Not me" steps above.

## Containing a compromised identity
- **SSO user:** Identity Center → user → delete active sessions; reset
  password and MFA. Role sessions last ≤ 1h (admin) / 4h (audit).
- **Root (management):** change password, replace MFA device, check for
  root access keys.
- Everything else: Terraform is the source of truth: `terraform plan`
  shows drift, `apply` restores it.

## Investigating
- The alert usually arrives before Event history (over 10 min behind on
  2026-10-22): an empty lookup → wait ~15 min.
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
**Quarantine an account** (contain first, investigate after). Every request
in the account is denied, including sessions an attacker already holds.
- **When:** a change went through that wasn't me → now. `AccessDenied`
  attempts that continue or that I can't explain within minutes → now.
  Not sure → treat as not me. (Cheap to undo, so press early.)
- **Press:** `aws organizations move-account --account-id <account-id> --source-parent-id <its-ou-id> --destination-parent-id <quarantine-ou-id> --profile management`
  (OU IDs: `aws organizations list-organizational-units-for-parent --parent-id <root-id> --profile management-audit --query 'OrganizationalUnits[].[Name,Id]' --output text`).
  Expect "guardrails changed: MoveAccount". Takes effect within ~1 min.
- **Still working:** the alert forwarder (alerts keep flowing), the
  `<account>-audit` role (investigate inside), AWS services (CloudTrail,
  Config, GuardDuty).
- **While quarantined:** don't apply `infra/management`: Terraform would
  move the account back out. The drift check fails for it (expected).
- **Release** (cause found and fixed): `move-account` back to its OU →
  admin session works again → `terraform plan` in management: "No changes".
- **Management can't be quarantined** (SCPs don't apply to it): break-glass
  (management root) instead.

**My SSO identity is compromised** (`by` is my SSO session, but the IP or
time isn't me). The identity reaches every account: one account's
containment isn't enough. *Step 2 drilled 2026-10-24; step 3 untested.*
1. **Contain members:** quarantine every member account with activity
   from it (each account's CloudTrail, `Username = <session name>`);
   unsure → all three.
2. **Cut the identity** via break-glass (management root, not my SSO
   login, which the attacker may hold): Identity Center → Users → disable
   the user. Stops new sessions in every account, management included.
   Expect two alerts: Identity Center changed + Change made as root
   (DisableUser).
3. **Management** can't be quarantined; sessions already issued last up
   to 1h → watch its alerts, undo changes as root.
4. **Eradicate:** find how it was stolen (phishing, laptop, leaked token)
   and fix that; new password + MFA device; check all 4 accounts'
   CloudTrail for the identity since the first unknown event.
5. **Recover:** re-enable the user → release the accounts → `terraform
   plan` in every root: "No changes".

**Changing protected alerting** (forwarders, hub, topic, access key responder: `ProtectAlerting`):
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

**Lab experiment that needs outside access** (the `DataPerimeter` RCP
blocks it): remove `lab` from `aws_organizations_policy_attachment.data_perimeter`
in `infra/management/rcp.tf` → plan + apply (expect "guardrails changed":
DetachPolicy) → experiment → put `lab` back → apply → re-check with an
anonymous request to a lab bucket (expect 403).

**Break-glass (root task in a member account):** from management, e.g.
`aws sts assume-root --target-principal <account-id> --task-policy-arn
arn=arn:aws:iam::aws:policy/root-task/<Task> --profile management --region us-east-1`
Tasks: IAMAuditRootUserCredentials, IAMCreateRootUserPassword,
IAMDeleteRootUserCredentials, S3UnlockBucketPolicy, SQSUnlockQueuePolicy.
15-minute session. Expect the AssumeRoot alert.
A root sign-in alert can come from any region (the sign-in endpoint's),
e.g. us-east-2.

**A bucket locked by its own policy** (admin gets "explicit deny in a
resource-based policy" on a bucket I own):
1. From management: `aws sts assume-root --target-principal <account-id>
   --task-policy-arn arn=arn:aws:iam::aws:policy/root-task/S3UnlockBucketPolicy
   --profile management --region us-east-1` → with the 15-minute
   credentials: `aws s3api delete-bucket-policy --bucket <bucket>`.
2. Expect two alerts: `AssumeRoot` (management) and `Change made as root:
   DeleteBucketPolicy`.
3. `terraform plan` + `apply` in that account → the correct policy is back.
Management's own buckets: root sign-in instead. Drilled 2026-10-23 (lab).

**Restore a Terraform state version** (`terraform plan` can't load the
state, or the state was changed by someone else):
1. List versions (newest first; `.tflock` rows are the lock file):
   `aws s3api list-object-versions --bucket tfstate-<account-id> --prefix
   <root>/terraform.tfstate --query 'Versions[0:5].[Key,VersionId,LastModified]'
   --output table --profile <account>`
2. Check the last version before the bad one: `aws s3api get-object …
   --version-id <id> <file>` → `jq '{serial, lineage}' <file>`: same
   lineage, serial fits. Not sure who wrote it → CloudTrail data events
   in the log archive. Delete the local copy after.
3. Copy it on top: `aws s3api copy-object --bucket tfstate-<account-id>
   --key <root>/terraform.tfstate --copy-source
   'tfstate-<account-id>/<root>/terraform.tfstate?versionId=<id>'
   --profile <account>` → new current version (locked 365 days).
4. `terraform plan`: `No changes` = only the state was touched. Anything
   else = AWS differs from that version: review before any apply.
Drilled 2026-10-23 (lab).

**Rebuild the site** (distribution deleted, bucket emptied or deleted;
fix the state first if needed). *Steps 1–2 untested (a real outage).*
1. `terraform plan` in `infra/live`: expect the distribution (and the
   bucket, if deleted) to be created, plus updates to what points at it:
   site bucket policy, 4 alias records, deploy role policy. Anything
   else → stop and look. Apply (CloudFront takes several minutes).
2. Site repo secret `CLOUDFRONT_DISTRIBUTION_ID` ← `terraform output
   -raw nojusniuklys_cloudfront_id`.
3. Redeploy: site repo → Actions → Deploy → Run workflow. Files back,
   cache cleared. (Tested 2026-10-23.)
4. Check: `curl -sI https://<domain>` → 200 + the security headers.

**Monthly alert test** (silence ≠ safety): try to create an IAM user in
lab (`aws iam create-user --user-name alert-test-<date> --profile lab`).
Expect `AccessDenied` (`ProtectBaseline`) and the email (`error:
AccessDenied`) within ~5 min; nothing to delete. Nothing → check the
SNS subscription (`ConfirmationWasAuthenticated` true, not pending) and
the rules' FailedInvocations metric.
Also check the drift check still runs: `gh run list --workflow drift.yml -L 3`
→ one run per day. GitHub only emails on failure: no runs = silence.

**If the email subscription is ever recreated:** don't click the
confirmation link; confirm via CLI with `--authenticate-on-unsubscribe true`
(see `infra/security/alerting.tf`).

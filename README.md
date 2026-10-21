# Hardening a Multi-Account AWS Organization
A real environment, run like production

I started with a bare AWS setup: an organization with three accounts, set up
by hand in the console, with almost no security in place: no working audit
trail, no threat detection, no budget alarm, and leftovers from old
experiments. I imported the organization itself into Terraform, added a
dedicated security account, then hardened all four accounts step by step:
fixing the problems I found, adding security services and guardrails that
follow established standards, and testing that each one actually works.

## What it looks like now

![Guardrails (SCPs) flow down from management to live, lab and security; all four accounts send their logs and security events into security, which emails me alerts.](architecture.drawio.svg)

Four accounts in one AWS Organization, each with one job:

- **management**: runs the organization: AWS Organizations, IAM Identity
  Center (single sign-on), billing and budgets, the service control
  policies (SCPs) every other account must follow, and the organization-wide
  CloudTrail trail. No workloads run here.
- **live**: production: the account for anything I actually run, whether
  that's websites, servers or databases.
- **lab**: deliberately insecure experiments. Some guardrails are relaxed on
  purpose (S3 and VPC public-access blocks), but it's logged and watched
  like every other account.
- **security**: the audit trail and the security tooling. Stores every
  account's CloudTrail and AWS Config logs (S3, KMS-encrypted, CloudTrail
  logs under Object Lock); delegated administrator for GuardDuty and
  Security Hub; hosts the alerting hub (EventBridge → SNS email).

Every account also gets the same baseline from one Terraform module: AWS
Config recording, IAM Access Analyzer, safe defaults (see Guardrails), and
a forwarder that sends its security events to the alerting hub.

The direction matters: evidence and alerts flow *into* security, and
guardrails flow *down* from management. Someone who takes over live or lab
can't erase the logs or silence the alerts, because those have already left
the account.

## What I built

### Identity and access

Who can get in, and how?

- **One way in: single sign-on.** I sign in through IAM Identity Center with
  MFA. There are no IAM users and no long-lived access keys anywhere. I have
  two levels of access in each account: admin, and a read-only auditor for
  scanning and browsing, so day-to-day work doesn't need admin rights.
- **No hidden back doors.** I found two admin roles left over from an older
  organization. They let anyone with admin in live become admin in lab and,
  worse, in management, which controls every account. One compromised
  account could have taken over the whole organization, and the roles
  didn't show up in single sign-on at all. I deleted them, along with the
  default admin role AWS creates in new accounts. Access is SSO only.
- **Root locked down.** Member accounts have no root passwords at all (AWS
  centralized root access). The rare root-only task runs as a short-lived
  session from management, and it triggers an alert. Management's root is
  the single break-glass login: MFA, password in a password manager, and an
  MFA backup kept off the phone.
- **Limits on my own tools.** I used an AI coding assistant (Claude Code)
  throughout. It can read and edit code, but it's denied every AWS command
  and every Terraform command that touches real infrastructure; I ran all
  of those myself.

### Logs as evidence

If something goes wrong, can I prove what happened, and trust the proof?

- **One trail for everything.** One organization trail records every
  account in every region and delivers to the security account. It also
  records every read of the Terraform state files (they map the whole
  infrastructure) and of the log archive itself.
- **Logs that can't be quietly changed.** The log bucket keeps every file
  under S3 Object Lock for a year and accepts writes only from the
  organization's trail. A service control policy stops even the security
  account's admins from changing the bucket or disabling its encryption key.
  The logs are encrypted with a key I control, so reading them needs that
  key as well as access to the bucket. CloudTrail also signs an hourly
  digest, so any edited or deleted file would show up.
- **Configuration history.** AWS Config records how every resource is
  configured and when it changes, for every account, stored in security.

### Detection and alerting

Would I find out about an attack?

- **Threat detection everywhere.** GuardDuty watches every account in all
  17 regions, run from the security account, and new accounts join
  automatically. It covers regions I don't use too, because that's exactly
  where an attacker would go.
- **Continuous checks.** Security Hub runs AWS's Foundational Security Best
  Practices checks in every account. IAM Access Analyzer flags anything
  shared outside an account, including with my own other accounts (the
  same kind of trust as the back-door roles).
- **Alerts that reach me.** Findings in a console nobody watches are no
  use. Every account forwards security-relevant events to one alerting hub
  in the security account, where eleven rules email me a one-line summary:
  root sign-in or use; changes to logging, detection or alerting; guardrail
  and single sign-on changes; new IAM users or keys; new external access;
  and GuardDuty findings of medium severity or higher. A service control
  policy stops member-account admins from switching their forwarding off,
  and a [runbook](runbook.md) says what to do for each alert.

### Guardrails

What's blocked outright, even for an admin?

Service control policies are set in management and apply to every other
account, admins included. They block whole categories of mistakes and
attacks instead of relying on someone noticing.

- **No leaving.** No account can leave the organization or be closed from
  inside it.
- **One region.** Member accounts can only build in us-east-1, so stolen
  credentials can't run crypto-miners in a region nobody watches. The
  read-only auditor and the security tooling keep what they need
  everywhere.
- **Small instances only.** EC2 is limited to a few small instance types,
  so a stolen session can't launch expensive GPU machines.
- **The baseline stays on.** Account admins can't switch off default
  encryption, the public-access blocks, Config recording or Access
  Analyzer. Lab's deliberate exceptions are written into the same policy.
- **Logs and alerts protected.** Nobody in a member account can change the
  log archive, its key or the alert forwarding.

Every account also has safe defaults: S3 and VPC public-access blocks
(except lab), default VPCs deleted (no network exists unless I build one),
encrypted disks, IMDSv2 for new instances, no public sharing of disk
snapshots or SSM documents, and an opt-out of AWS using my data to train
AI services, locked so no account can turn it back on.

### Cost

Would a forgotten resource or a crypto-miner surprise me on the bill?

- **A budget that alerts.** A $10 monthly budget emails me at half, at
  the full amount, and when the forecast says I'll go over. It has already
  paid off: the halfway alert arrived mid-month and led me to a forgotten
  WAF web ACL (firewall rules) billing about $5 a month on a disabled
  CloudFront distribution. I deleted it.
- **Anomaly alerts at my scale.** AWS's default cost-anomaly alert only
  fired for spikes of at least $100 and 40% above expected, which would
  never happen at this budget. It now fires at $5, half the monthly
  budget.

## Results

- **41 findings:** 1 critical, 6 high, 9 medium, 21 low and 4
  informational. Every critical, high and medium finding is fixed. The
  critical one, a path from one compromised account to the whole
  organization, I found by reviewing the roles myself, before running any
  scanner.
- **Scanners as a second opinion** (Prowler, same version and settings
  before and after; us-east-1, where everything runs): failed checks down
  by a third (402 → 271), high-severity failures halved (79 → 39), and 47
  checks fixed completely.
- **Every remaining failure is explained.** Most of the 271 are deliberate
  decisions with a written reason (for example, EventBridge alerts instead
  of CIS's CloudWatch alarms) or checks for services I don't use; a few are
  scanner errors I traced to Prowler's own code. The 7 critical ones: my
  admin role's AdministratorAccess (4), app-based root MFA (1), scanner
  errors (2) — see Limits.
- **Code:** Checkov reports nothing unexplained: 113 checks pass, 34
  accepted ones carry their reason in the code, and the one failure
  (CloudFront access logging on my website) is a known gap, left failing
  on purpose as a reminder. No secrets in the repository (gitleaks).

## Limits and trade-offs

What I deliberately didn't do, and why:

- **Management is the one account guardrails can't reach.** Service
  control policies never apply to it, so nothing runs there, it's reached
  only through single sign-on with MFA, and every guardrail change sends
  an alert.
- **Admin access is broad.** My admin role uses AWS's AdministratorAccess
  policy; single sign-on, MFA and short sessions limit the risk. A
  narrower admin role is the first thing I'd tighten with more people.
- **Root uses app-based MFA**, not a hardware key. It's the break-glass
  login only, and any use triggers an alert.
- **One security account** instead of AWS's recommended separate
  log-archive and security-tooling accounts. At this size the split adds
  overhead without much benefit; it's the first thing I'd change as the
  organization grows.
- **One region.** The baseline covers us-east-1 only; the other regions
  are locked off and watched by GuardDuty instead of configured.
- **Alerts are email only.** No paging, ticketing or SIEM, and
  investigating means reading the logs directly.
- **The AI assistant's limits stop mistakes, not attackers.** The rules
  match command text, so a determined attacker could get around them.
  Separate read-only credentials for the assistant would be the real
  boundary.

## How I tested it

### Identity and access
- Read-only auditor: reads every account's configuration (the scanners ran
  with it), but downloading a Terraform state file returns 403.
- Break-glass: a real root session from management triggered an alert
  email. Root can't be used quietly.
- Assistant: its attempts to run AWS or `terraform apply`, including
  disguised variants, were denied.

### Logs as evidence
- Tamper protection: a security-account admin trying to change the log
  bucket, and separately the key's policy, was denied by the service
  control policy.
- Integrity: the signed digests check out for all 4 accounts: 6,246 of
  6,246 log files valid since the trail started, and still valid after the
  switch to the new key.

### Detection and alerting
- Every test ran through the live alerting chain, end to end: a real IAM
  user created in lab, a GuardDuty sample finding generated in a region I
  don't use, and a lab admin trying to remove the forwarding. Each one
  reached my inbox; the last was also blocked.
- Testing found two gaps, both fixed: anyone with an alert email could
  unsubscribe me (now needs an AWS login), and a blocked attempt read like
  a real change (alerts now show the error code).

### Guardrails
- Region lock: a lab admin in Ireland was denied; the read-only auditor
  there was allowed; a GuardDuty alert from Ireland still arrived.
- Instance types: launching a GPU instance was denied, a small one was
  allowed (dry runs).
- Baseline: a live admin trying to turn off default encryption, or to
  change S3 public-access settings, was denied; lab's exception still
  worked.

## What's in this repo

- `infra/`: all the Terraform, one folder per account (`management`,
  `security`, `live`, `lab`) plus shared `modules/`; each folder is
  applied on its own. `modules/account-baseline` is the set of defaults
  every account gets.
- Account IDs and emails aren't in the code: each folder reads them from
  a private `terraform.tfvars` (and the state bucket from `backend.hcl`).
  The `.example` files show the shape.
- `infra/live` also runs my personal website (S3 + CloudFront, deployed
  from GitHub without stored keys).
- [`runbook.md`](runbook.md): what I do when each alert arrives.

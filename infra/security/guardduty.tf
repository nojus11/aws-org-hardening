locals {
  # GuardDuty paid protection plans: S3 on; the rest off until a workload
  # needs them (e.g. malware protection for Project 2 labs). Newer plans
  # (AI_PROTECTION, AI_ANALYST — off by default, not in every region) are left
  # to AWS; new plans are caught by cost checks and Prowler, not Terraform.
  guardduty_protection_plans = {
    S3_DATA_EVENTS         = { status = "ENABLED" }
    EKS_AUDIT_LOGS         = { status = "DISABLED" }
    EBS_MALWARE_PROTECTION = { status = "DISABLED" }
    RDS_LOGIN_EVENTS       = { status = "DISABLED" }
    LAMBDA_NETWORK_LOGS    = { status = "DISABLED" }
    RUNTIME_MONITORING     = { status = "DISABLED" }
  }

  # Org accounts to add as GuardDuty members (security itself is the admin).
  # IDs and emails from terraform.tfvars rather than read from management's state.
  guardduty_members = var.member_accounts
}

# Every region enabled in this account (17), so a new default region is
# covered automatically.
data "aws_regions" "enabled" {}

module "guardduty" {
  source   = "../modules/guardduty-region"
  for_each = toset(data.aws_regions.enabled.names)

  region           = each.key
  protection_plans = local.guardduty_protection_plans
  members          = local.guardduty_members

  # Management had its own detector before joining (AWS defaults: extra paid
  # plans on) — the admin sets its plans explicitly.
  plans_enforced_on = local.guardduty_members.management.account_id

  alert_hub_bus_arn        = aws_cloudwatch_event_bus.org_events.arn
  alert_forwarder_role_arn = module.baseline.alert_forwarder_role_arn
}

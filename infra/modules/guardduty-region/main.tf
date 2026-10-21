# This account's GuardDuty "on switch" in one region.
resource "aws_guardduty_detector" "this" {
  region = var.region
  enable = true

  # Updates to existing findings reach EventBridge (our future alerts) every
  # 15 min instead of the default 6 hours. New findings go out immediately.
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}

# Each established paid protection plan explicitly on or off. Newer plans
# and plan sub-settings are left to AWS (see security/guardduty.tf).
resource "aws_guardduty_detector_feature" "this" {
  for_each = var.protection_plans

  region      = var.region
  detector_id = aws_guardduty_detector.this.id
  name        = each.key
  status      = each.value.status

  lifecycle {
    # AWS keeps adding sub-settings to plans (e.g. RDS_DATA_RISK, Oct 2026).
    # Their parent plans are off, so let AWS manage them; manage specific
    # ones explicitly if a plan is turned on.
    ignore_changes = [additional_configuration]
  }
}

# As GuardDuty admin: auto-enable GuardDuty for accounts that join the org
# from now on (existing accounts are added as members below). Members can't
# turn GuardDuty off.
resource "aws_guardduty_organization_configuration" "this" {
  region                           = var.region
  detector_id                      = aws_guardduty_detector.this.id
  auto_enable_organization_members = "ALL"
}

# Org rule for plans, applied when an account joins: ENABLED plans are turned
# on (ALL); DISABLED ones are left alone (NONE = "don't turn on" — it never
# turns a plan off; see member_detector_feature below).
resource "aws_guardduty_organization_configuration_feature" "this" {
  for_each = var.protection_plans

  region      = var.region
  detector_id = aws_guardduty_detector.this.id
  name        = each.key
  auto_enable = each.value.status == "ENABLED" ? "ALL" : "NONE"

  lifecycle {
    ignore_changes = [additional_configuration] # same reason as above
  }
}

# Existing org accounts don't join automatically — add them as members.
# Joining switches GuardDuty on (creating a detector if the account has none)
# and applies the org rule above.
resource "aws_guardduty_member" "this" {
  for_each = var.members

  region      = var.region
  detector_id = aws_guardduty_detector.this.id
  account_id  = each.value.account_id
  email       = each.value.email

  # The org rule must exist before anyone joins
  depends_on = [aws_guardduty_organization_configuration.this]

  lifecycle {
    # Org accounts join directly: AWS doesn't keep the email (only used for
    # invitations) and reports them as invited. Don't recreate over it.
    ignore_changes = [email, invite]
  }
}

# Accounts that had GuardDuty before joining keep their old plan settings —
# the org rule only says "don't turn on", not "turn off". So the admin sets
# that member's plans explicitly from the same map.
resource "aws_guardduty_member_detector_feature" "this" {
  for_each = var.plans_enforced_on == null ? {} : var.protection_plans

  region      = var.region
  detector_id = aws_guardduty_detector.this.id
  account_id  = var.plans_enforced_on
  name        = each.key
  status      = each.value.status

  depends_on = [aws_guardduty_member.this]

  lifecycle {
    ignore_changes = [additional_configuration] # same reason as above
  }
}

# Forward every finding in this region to the alerting hub (us-east-1), which
# decides what is worth an email. Otherwise findings never leave their region.
resource "aws_cloudwatch_event_rule" "forward_findings" {
  region      = var.region
  name        = "forward-guardduty-findings"
  description = "Forward GuardDuty findings to the alerting hub"
  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
  })
}

resource "aws_cloudwatch_event_target" "forward_findings" {
  region   = var.region
  rule     = aws_cloudwatch_event_rule.forward_findings.name
  arn      = var.alert_hub_bus_arn
  role_arn = var.alert_forwarder_role_arn
}

# Make the security account GuardDuty's delegated administrator in every
# enabled region (GuardDuty is regional, so the designation is too).
data "aws_regions" "enabled" {}

resource "aws_guardduty_organization_admin_account" "security" {
  for_each = toset(data.aws_regions.enabled.names)

  region           = each.key
  admin_account_id = aws_organizations_account.security.id

  # Org-wide GuardDuty access must be on first
  depends_on = [aws_organizations_organization.this]
}

# Management's own GuardDuty in each region. AWS requires the management
# account to have GuardDuty on before it can join as a member.
resource "aws_guardduty_detector" "management" {
  #checkov:skip=CKV2_AWS_3:org config lives in infra/security (delegated admin); not visible from this root
  for_each = toset(data.aws_regions.enabled.names)

  region                       = each.key
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES" # same as the admin
}
